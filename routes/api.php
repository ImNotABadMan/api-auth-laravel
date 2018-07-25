<?php

use Illuminate\Http\Request;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});
Route::match(['get', 'post'], 'login', 'AuthController@login');
Route::match(['get', 'post'], 'whoiam', 'AuthController@whoiam');
Route::match(['get', 'post'], 'whoiamDecode', 'AuthController@whoiamDecode');

