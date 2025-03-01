<?php
namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;

class UserSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        User::create([
            'name'              => 'System Admin',
            'email'             => 'admin@gmail.com',
            'role'              => 'ADMIN',
            'email_verified_at' => now(),
            'password'          => Hash::make('1234'),
        ]);

        User::create([
            'name'=>'Test User',
            'email'=>'test@gmail.com',
            'dob'=>'2000-03-01',
            'address'=>'Dhaka',
            'period_duration'=>4,
            'period_type'=>'Regular',
            'fixed_days'=>7,
            'last_period_date'=>'2025-03-01',
            'phase_name'=>'Ovulation',
            'subscription_type'=>'Trial',
            'email_verified_at'=>now(),
            'password'          => Hash::make('1234'),
        ]);
    }
}
