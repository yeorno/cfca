Demo运行

1、安装对应版本的PHP

2、安装运行时环境（glibc库等）

3、修改PHP的配置文件php.ini
修改php.ini，使php允许加载扩展，并将当前扩展添加到其扩展列表中
enable_dl = On
extension=libSADKExtension.so.3.4.0.1



4、在Demo\RSA目录下替换证书和cer文件 
pfx为私钥文件请妥善保管不要泄露给他人
cer文件为颁发者公钥，用来验证汇付公钥

5、配置 cfcalog.conf  cfca日志文件

6、通过命令行终端运行Demo文件 
php huifuCFCALinuxDemo.php

Msg PKCS7-attached Sign 为使用pfx证书加签
PKCS7-attached-Verify   为验证汇付的签名
cfca_verifyCertificate 为验证证书链合法性
cfca_getCertificateInfo 为获取证书信息（非必要）