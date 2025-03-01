<?php

use App\Http\Controllers\api\AuthController;
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
        Route::get('check-token', [AuthController::class, 'validateToken'])->name('validateToken');
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

        });

        // admin routes
        Route::middleware('admin')->prefix('admin/')->as('admin')->group(function () {

        });
    });
});
