<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Jwt\BJwtAuth;


class AuthController extends Controller
{
    //
    public function login()
    {
        $jwt = new BJwtAuth();
        $token = $jwt->getToken();
        $auth = $jwt->isAuth();

        return [
            config('jwt'),
            compact('token', 'auth'),
            app('BJwtAuth')->getToken(),
            BJwtAuth::testFacade()
        ];
    }
}
