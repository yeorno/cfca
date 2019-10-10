<?php

class HuifuCFCA
{
    private $apiUrl                 = 'http://mertest.chinapnr.com/npay/merchantRequest';                       //app+ 商户交易接口,此处使用的是联调环境地址
    private $strSignAlg             = 'RSA';                     //RSA证书类型
    private $strPfxPassword         = '888888';                 //导出时设置的密码
    private $strHashAlg             = 'SHA-256';                //加签算法
    private $strPfxFilePath        = './RSA/AS0381.pfx';      //汇付下发的证书，此处换成商户自己的证书 .pfx 格式 加签使用
    private $strTrustedCACertFilePath = './RSA/CFCA_ACS_TEST_OCA31.cer|./RSA/CFCA_ACS_TEST_CA.cer'; //汇付下发的.cer证书 ，需要一对证书 解签使用
    private $strLogCofigFilePath  = './cfcalog.conf';          //CFCA log 目录

    public function __construct()
    {
        $this->getCFCAInitialize();     //CFCA工具初始化
    }

    /**
     * CFCA工具初始化
     */
    private function getCFCAInitialize()
    {
        $nResult = cfca_initialize($this->strLogCofigFilePath);
        if (0 != $nResult) {
            //记录log
            echo new Exception("\n cfca_Initialize error:".$nResult."\n");
        }
    }

    /**
     * 调用接口  此处是APP + 的接口请求
     *
     * @return string
     */
    public function apiRequest(){
        //请求参数，依据商户自己的参数为准
        $requestParam['version'] = '10';
        $requestParam['cmd_id'] = '202';
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

        //接口请求参数
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
        $sourceData = $this->getCFCASignSourceData($checkValue);
        $SignCertContent = !empty($sourceData['strMsgP7AttachedSignCertContent']) ? $sourceData['strMsgP7AttachedSignCertContent'] : '';

        //验证返回数据的CFCA证书有效性
        $verifyCertificat = $this->verifyCertificat($SignCertContent);
        $signSourceData = '';
        if(!empty($sourceData['strMsgP7AttachedSource']) && $verifyCertificat){  //校验证书有效性
            $signSourceData =  $sourceData['strMsgP7AttachedSource'];
        }

        return $signSourceData;
    }

    /**
     * CFCA 加签方法
     *
     * @param $strSignSourceData  base64 encode 加签原串
     * @return string  base64 encode 加签串
     */
    private function CFCASignature($strSignSourceData){
        $strMsgPKCS7AttachedSignature = '';//加签生成串 ,输出变量，无需传值

        try{
            //调用加签方法
            $nResult = cfca_signData_PKCS7Attached($this->strSignAlg, $strSignSourceData,
                $this->strPfxFilePath, $this->strPfxPassword, $this->strHashAlg,$strMsgPKCS7AttachedSignature);

            //加签方法异常判断及记录
            if (0 != $nResult) {
                //记录log
                echo new Exception("\n cfca_signData_PKCS7Attached error:".$nResult."\n");
            }

        }catch (Exception $e){
            throw new Exception("\n cfca_verifyCertificate error:".$e."\n");
        }

        return base64_encode($strMsgPKCS7AttachedSignature);
    }

    /**
     * CFCA 验证签名数据
     *
     * @param $signature
     * @return array
     */
    private function getCFCASignSourceData($signature){
        $strMsgP7AttachedSignCertContent = '';  //PKCS#7 中的签名证书  输出变量，无需传值
        $strMsgP7AttachedSource = '';   //签名原文字符串  输出变量，无需传值

        try{
            //调用验证签名数据方法
            $nResult = cfca_verifyDataSignature_PKCS7Attached($this->strSignAlg, base64_decode($signature),
                $strMsgP7AttachedSignCertContent,$strMsgP7AttachedSource);

            //验证签名方法异常判断及记录
            if (0 != $nResult) {
                //记录log
                echo new Exception("cfca_verifyDataSignature error:".$nResult);
            }

        }catch (Exception $e){
            //记录log
            throw new Exception("cfca_verifyDataSignature_PKCS7Attached error:".$e);
        }

        return array(
            'strMsgP7AttachedSource' => $strMsgP7AttachedSource,
            'strMsgP7AttachedSignCertContent' => $strMsgP7AttachedSignCertContent,
        );
    }

    /**
     * CFCA 证书有效性验证
     *
     * @param $strMsgP7AttachedSignCertContent PKCS#7 中的签名证书 base64
     * @return int
     */
    private function verifyCertificat($strMsgP7AttachedSignCertContent = ''){
        $nCertVerifyFlag = '4'; //验证证书链完整性
        $strTrustedCACertFilePath = $this->strTrustedCACertFilePath;
        $isVerify = false;

        try{
            //调用验证方法
            $nResult = cfca_verifyCertificate($strMsgP7AttachedSignCertContent, $nCertVerifyFlag, $strTrustedCACertFilePath,"");
            if (0 == $nResult) {  // 0 为验证通过 ，其他验证失败
                $isVerify = true;
            }else{
                //记录log
                echo new Exception("cfca_verifyCertificate error:".$nResult);
            }

        }catch (Exception $e){
            //记录log
            throw new Exception("cfca_verifyCertificate error:".$e);
        }

        return $isVerify;
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

    /**
     *CFCA工具结束
     */
    public function __destruct()
    {
        cfca_uninitialize();
    }

}
//调用
$demoObj = new HuifuCFCA();
$data = $demoObj->apiRequest();

print_r('<pre/>');
print_r($data);
