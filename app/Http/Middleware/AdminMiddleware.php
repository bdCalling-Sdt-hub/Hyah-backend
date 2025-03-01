<?php

namespace App\Http\Middleware;

use Closure;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class AdminMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        try {
            $user = Auth::user();

            if ($user->role == 'ADMIN') {
                return $next($request);
            }

            return response()->json([
                'message' => 'You are not an admin.',
            ], 401);

        } catch (Exception $exception) {
            return response()->json([
                'message' => 'Unauthorized: ' . $exception->getMessage(),
            ], 401);
        }
    }
}
