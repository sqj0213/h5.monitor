<?php

/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all of the routes for an application.
| It's a breeze. Simply tell Laravel the URIs it should respond to
| and give it the Closure to execute when that URI is requested.
|
*/
/*
Route::get('/', function()
{
	return View::make('hello');
});
*/
Route::get('/', 'HomeController@showWelcome');
Route::get('/auth', 'AuthController@auth');
Route::get('/auth/test', 'AuthController@test');
Route::get('/getuserinfo', 'AuthController@checkApiInvalid');
