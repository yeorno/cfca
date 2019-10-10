<?php

class HuifuCFCA
{
    private $apiUrl                 = 'http://mertest.chinapnr.com/npay/merchantRequest';   // app+ 商户交易接口,此处使用的是联调环境地址
    private $strSignAlg             = 'RSA';                     //RSA证书类型
    private $strPfxPassword         = '888888';                 //导出时设置的密码
    private $strHashAlg             = 'SHA-256';                //加签算法
    private $strPfxFilePath        = './RSA/AS0381.pfx';       //汇付天下发的证书，此处换成商户自己的证书  此处换成商户自己的证书 .pfx 格式 加签使用
    private $strTrustedCACertFilePath = './RSA/CFCA_ACS_TEST_OCA31.cer|./RSA/CFCA_ACS_TEST_CA.cer'; //汇付下发的.cer证书 ，需要一对证书 验签使用
    private $cryptoAgentServerObj = '';                         //CFCA obj

    public function __construct()
    {
        // Create the object of COM by its ProgID
        // If your php is compiled with x64, you need to use CryptoKit.standard.x64.dll, its ProgID is:CryptoKit.CryptoAgent.Server.Standard.x64.1
        // If your php is compiled with x86, you need to use CryptoKit.standard.x86.dll, its ProgID is:CryptoKit.CryptoAgent.Server.Standard.x86.1
        // Change next line according to your php
        //注册windows com 服务,依据自己PHP编译版本选择对应参数，此处使用的是32位编译版本的PHP
        $this->cryptoAgentServerObj = new \COM("CryptoKit.CryptoAgent.Server.Standard.x86.1", NULL, CP_UTF8);
    }

    /**
     * 调用接口  此处是APP + 的接口请求
     *
     * @return string
     */
    public function apiRequest(){
        //请求参数，依据商户自己的参数为准
        $requestParam['version'] = '10';
        $requestParam['cmd_id'] = '202'; //取现接口
        $requestParam['mer_cust_id'] = '6666000000002619';
        $requestParam['user_cust_id'] = '6666000000054387';
        $requestParam['order_date'] = '20180918';
        $requestParam['order_id'] = '201809189000001';
        $requestParam['trans_amt'] = '1.00';
        $requestParam['cash_bind_card_id'] = '76247';
        $requestParam['fee_obj'] = '';
        $requestParam['fee_acct_id'] = '';
        $requestParam['cash_type'] = '02030000';
        $requestParam['bg_ret_url'] = 'http://192.168.0.74:8001/npayCallBack/asyncHandle.json';
        $requestParam['mer_priv'] = 'test_mer_priv';
        $requestParam['extension'] = 'test_extension';

        //加签
        $strSignSourceData = json_encode($requestParam);
        $cfcaSign = $this->CFCASignature($strSignSourceData);

        //取现接口请求
        $param = [
            'requestData'  => [
                'cmd_id' => $requestParam['cmd_id'],
                'mer_cust_id' => $requestParam['mer_cust_id'],
                'version' => $requestParam['version'],
                'check_value' => $cfcaSign,
            ],
            'headers' => ['Content-type' => 'application/x-www-form-urlencoded;charset=UTF-8']
        ];
        $requestData = $this->requestData($param);
        $checkValue = json_decode($requestData['body'],1)['check_value'];

        //验证接口返回的签名数据
        $strBase64CertContent = $this->verifyDataSignature($checkValue);

        //验证返回数据的CFCA证书有效性
        $verifyCertificat = $this->verifyCertificat($strBase64CertContent);

        //获取解签数据
        $signSourceData = '';
        if($verifyCertificat){  //校验证书有效性
            $signSourceData = $this->getCFCASignSourceData($checkValue);
        }

        return $signSourceData;
    }

    /**
     * cfca 加签方法
     *
     * @param $strSignSourceData 待签名字符串
     * @return string
     */
    private function CFCASignature($strSignSourceData){
        $strMsgPKCS7AttachedSignature = '';

        try{
            $strMsgPKCS7AttachedSignature = $this->cryptoAgentServerObj->SignData_PKCS7Attached($this->strSignAlg, $strSignSourceData,
                $this->strPfxFilePath, $this->strPfxPassword, $this->strHashAlg);

        }catch (Exception $e){
            $strErrorMsg = $this->cryptoAgentServerObj->GetLastErrorDesc();

            return  $strErrorMsg;
        }

        return base64_encode($strMsgPKCS7AttachedSignature);
    }

    /**
     * CFCA 验证签名数据
     * @param $signature Base64编码的签名
     * @return string
     */
    private function verifyDataSignature($signature){
        $strBase64CertContent = "";

        try{
            $strBase64CertContent = $this->cryptoAgentServerObj->VerifyDataSignature_PKCS7Attached($this->strSignAlg,base64_decode($signature));

        }catch (Exception $e){
            $strErrorMsg = $this->cryptoAgentServerObj->GetLastErrorDesc();
            //记录log
            throw new Exception("\n verifyDataSignature error:".$strErrorMsg."\n");
        }

        return $strBase64CertContent;
    }

    /**
     * CFCA 解签获取签名数据
     * @param $signature
     * @return string
     */
    private function getCFCASignSourceData($signature){
        $strMsgP7AttachedSource = '';

        try{
            $strMsgP7AttachedSource = $this->cryptoAgentServerObj->GetSignSourceData(base64_decode($signature));

        }catch (Exception $e){
            $strErrorMsg = $this->cryptoAgentServerObj->GetLastErrorDesc();

            return  $strErrorMsg;
        }

        return $strMsgP7AttachedSource;
    }

    /**
     * CFCA 证书有效性验证
     *
     * @param $strBase64CertContent 签名证书内容 base64
     * @return bool
     */
    private function verifyCertificat($strBase64CertContent = ''){
        $nCertVerifyFlag = '4'; //验证证书链完整性
        $strTrustedCACertFilePath = $this->strTrustedCACertFilePath;

        try{
            //调用验证方法
            $nResult = $this->cryptoAgentServerObj->VerifyCertificate($strBase64CertContent, $nCertVerifyFlag, $strTrustedCACertFilePath,"");

            if (!$nResult) {  // true 为验证通过 ，其他验证失败
                //记录log
                echo new Exception("verifyCertificat error:".$nResult);
            }

        }catch (Exception $e){
            //记录log
            throw new Exception("verifyCertificat error:".$e);
        }

        return $nResult;
    }

    /**
     * 请求接口返回数据
     * @param $param
     * @return array
     */
    private function requestData($param)
    {
        try{
            // 请求接口所以参数初始化
            $data = [
                'url'         => $this->apiUrl,          // 接口 url
                'requestData' => $param['requestData'], // 请求接口参数
                'headers'     =>$param['headers']
            ];

            $res = $this->httpPostRequest($data['url'],$data['headers'],$data['requestData']);

        } catch (\Exception $e) {
            //记录log
            throw new Exception("api requestData error :".$e);
        }

        return [
            'status' => $res['info']['http_code'],
            'body' => $res['body']
        ];
    }

    /**
     * curl post 请求方法
     *
     * @param string $url
     * @param array $header
     * @param array $requestData
     * @return array
     */
    private function httpPostRequest($url = '',$header = array(),$requestData = array()){
        $curl = curl_init();
        curl_setopt ( $curl, CURLOPT_HTTPHEADER,$header);
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_POST, true);
        curl_setopt($curl, CURLOPT_POSTFIELDS,http_build_query($requestData));
        $res = curl_exec($curl);
        $info = curl_getinfo($curl);
        $error = curl_error($curl);
        curl_close($curl);

        return [
            'body' => $res,
            'info' => $info,
            'error' => $error,
        ];
    }

}
//调用接口
$demoObj = new HuifuCFCA();
$data = $demoObj->apiRequest();

print_r('<pre/>');
print_r($data);