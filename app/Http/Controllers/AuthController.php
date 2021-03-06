<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Jwt\BJwtAuth;


class AuthController extends Controller
{
    private $_jwt;

    public function __construct()
    {
        $this->middleware('apiAuth')->except(['login']);
    }

    public function login(Request $request)
    {
        $credit = $request->all(['email', 'password']);
        $validator = Validator::make($credit, [
            'email'     => 'required',
            'password'  => 'required|min:6',
        ]);
        if( $validator->fails() ){
            return $this->jsonReturn(1,$validator->errors());
        }
        $jwt = new BJwtAuth();
        $jwt->exp = 60;

        if( !$jwt->isCan($credit) ){
            return $this->jsonReturn(1, 'UnAuthorized');
        }

        $header = [
            'typ'   => 'jwt',
            'alg'   => 'HS256'
        ];
        $payload = [
            'iss'   => 'bin',
            'sub'   => 'test',
            'iat'   => date('Y-m-d H:i:s'),
            'exp'   => $jwt->exp,
            'email' => $credit['email']
        ];
        $token = $jwt->encodeToken($header, $payload);
        $data = [
            'access_token'  => $token,
            'type'          => 'bearer',
            'exp'           => $jwt->exp
        ];
        return $this->jsonReturn(0, 'login success', $data);
    }

    public function whoiam()
    {
        $jwt = new BJwtAuth();
        $jwt->exp = 60;

        $token = \request('token');

        $tokenDecode = $jwt->decodeToken($token, true);

        $payload = [
            'iss'   => 'bin',
            'sub'   => 'test',
            'iat'   => $tokenDecode["payload"]['iat'],
            'exp'   => $jwt->exp,
            'email' => 'binz@qq.com',
            'id'    => 1,
        ];

        return $this->jsonReturn(0, 'success', $jwt->encodeToken($tokenDecode['header'], $payload));
    }

    public function whoiamDecode()
    {
        $jwt = new BJwtAuth();
        $jwt->exp = 60;

        $token = \request('token');

        $jwt = new BJwtAuth();


        $tokenDecode = $jwt->decodeToken($token, true);

        return $this->jsonReturn(0, 'success', $tokenDecode);
    }
}
