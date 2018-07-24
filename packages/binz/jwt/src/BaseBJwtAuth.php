<?php
/**
 * Created by PhpStorm.
 * User: IT
 * Date: 2018/7/24
 * Time: 16:45
 */

namespace Jwt;


class BaseBJwtAuth
{
    protected $_config;

    protected $_header = [
      'typ' => 'typ', // 接口类型
      'alg' => 'alg', // 加密类型
    ];

    protected $_payload = [
        'iss' => 'iss', // 发布token的一方
        'sub' => 'sub', // token的主题
        'aud' => 'aud', // 接受token的一方
        'exp' => 'exp', // 过期时长
        'ndf' => 'ndf', // 在什么时间前不能使用
        'iat' => 'iat', // token创建时间
        'jti' => 'jti', // 唯一标识，用来一次性token
    ];

    protected $_alg;

    protected $_exp;

    protected $_algMap = [
        'HS256' => 'sha256'
    ];

    public function __construct()
    {
        $this->_config = config('jwt');
    }

    public function __get($name)
    {
        // TODO: Implement __get() method.
        if( is_array($name) ) {
            $keyArr = implode('.', $name);
            $attr = '_' . $keyArr[0];
            if( isset($this->$attr) ){
                return $this->$attr[$keyArr[1]];
            }
        }
        if( is_string($name) ){
            $attr = '_' . $name;
            return $this->$attr;
        }

        return null;
    }

    public function getToken($header, $payload, $config = [])
    {
        if( !empty($config) && isset($config['jwt_secret']) ){
            $this->_config['jwt_secret'] = $config['jwt_secret'];
        }

        $this->_alg = $header['alg'];
        $this->_exp = $payload['exp'];



        return 'getToken';
    }

    public function decodeToken($token)
    {
        list($header, $paylood, $signature) = explode('.', $token);

    }

    public function encodeToken()
    {

    }

    public function outOfTime()
    {
        return $this->_payload['iat'] + $this->_payload['exp'] < time();
    }

    public function isAuth($token)
    {
        list($header, $payload, $signature) = explode('.', $token);

        $this->_header['alg'] = $header['alg'];
        $this->_payload['iat'] = $payload['iat'];
        $this->_payload['exp'] = $payload['exp'];
        if( $this->outOfTime() ){
            return ['code' => 1, 'message' => 'token expired'];
        }

        $headerDecode = json_decode(base64_decode($header));

        if( !isset($headerDecode['alg']) ){
            return false;
        }

        $localSignature = hash_hmac($this->_algMap[$headerDecode['alg']],$header . '.' . $payload, config('jwt_sercret'));

        if( strpos($signature, $localSignature) !== 0){
            return false;
        }

        return true;
    }
}