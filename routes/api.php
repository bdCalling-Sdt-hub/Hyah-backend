<?php

use App\Http\Controllers\api\AuthController;
use App\Http\Controllers\api\Frontend\MyNoteController;
use Illuminate\Support\Facades\Route;

Route::group(['middleware' => 'api'], function ($router) {

    Route::prefix('auth/')->group(function () {
        // registration routes
        Route::post('social-login', [AuthController::class, 'socialLogin']);
        Route::post('register', [AuthController::class, 'register']);
        Route::post('login', [AuthController::class, 'login']);
        Route::post('otp-verification', [AuthController::class, 'otpVerify']);
        Route::post('forget-password', [AuthController::class, 'forgetPassword']);
        Route::post('reset-password', [AuthController::class, 'resetPassword']);
        Route::get('check-token', [AuthController::class, 'validateToken']);
        Route::get('get-profile', [AuthController::class, 'getProfile']);
    });

    // verified user routes
    Route::middleware(['auth:api', 'verified.user'])->prefix('/')->group(function () {
        // profile
        Route::get('profile', [AuthController::class, 'profile']);
        Route::post('edit-profile', [AuthController::class, 'editProfile']);
        Route::post('change-password', [AuthController::class, 'changePassword']);
        Route::post('refresh', [AuthController::class, 'refresh']);
        Route::post('logout', [AuthController::class, 'logout']);

        // user routes
        Route::middleware('user')->as('user')->group(function () {
            Route::apiResource('my-note', MyNoteController::class)->only('store', 'update', 'destroy');
        });

        // admin routes
        Route::middleware('admin')->prefix('admin/')->as('admin')->group(function () {

        });
    });
});
