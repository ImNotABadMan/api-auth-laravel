<?php
/**
 * Created by PhpStorm.
 * User: IT
 * Date: 2018/7/24
 * Time: 14:13
 */

namespace Jwt;

Class BJwtAuth extends BaseBJwtAuth
{



    public function isAuth()
    {
        return 'isAuth';
    }

    public static function testFacade()
    {
        return 'JwtFacade';
    }
}