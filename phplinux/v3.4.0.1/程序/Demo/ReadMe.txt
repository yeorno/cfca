Demo����

1����װ��Ӧ�汾��PHP

2����װ����ʱ������glibc��ȣ�

3���޸�PHP�������ļ�php.ini
�޸�php.ini��ʹphp���������չ��������ǰ��չ��ӵ�����չ�б���
enable_dl = On
extension=libSADKExtension.so.3.4.0.1



4����Demo\RSAĿ¼���滻֤���cer�ļ� 
pfxΪ˽Կ�ļ������Ʊ��ܲ�Ҫй¶������
cer�ļ�Ϊ�䷢�߹�Կ��������֤�㸶��Կ

5������ cfcalog.conf  cfca��־�ļ�

6��ͨ���������ն�����Demo�ļ� 
php huifuCFCALinuxDemo.php

Msg PKCS7-attached Sign Ϊʹ��pfx֤���ǩ
PKCS7-attached-Verify   Ϊ��֤�㸶��ǩ��
cfca_verifyCertificate Ϊ��֤֤�����Ϸ���
cfca_getCertificateInfo Ϊ��ȡ֤����Ϣ���Ǳ�Ҫ��