<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Support\Facades\Validator;
use Jwt\BJwtAuth;

class ApiAuthMiddleware
{
    private $_jwt;

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $tokenName = config('jwt.jwt_token_name', 'token');
        $token = $request->get($tokenName);

        $this->_jwt = new BJwtAuth();
        $this->_jwt->exp = config('jwt.exp', $this->_jwt->exp);

        $errors = $this->_validateToken([$tokenName => $token]);

        if( $errors ){
            return  response( ['code' => 1, 'message' => $errors]);
        }
        if( $this->_isAuth($token) ){
            return response(['code' => 1, 'message' => 'UnAuthorized']);
        }
        if( $this->_isOutOfTime($token) ){
            return response(['code' => 1, 'message' => 'token expired']);
        }
        return $next($request);
    }

    protected function _validateToken($token)
    {
        $validator = Validator::make($token, [
//            key($token)[0]  => 'required'
        ]);

        return $validator->fails() ? $validator->errors() : [];
    }

    protected function _isOutOfTime($token)
    {
        return $this->_jwt->outOfTime($token);
    }

    protected function _isAuth($token)
    {
        return $this->_jwt->isAuth($token);
    }

}

