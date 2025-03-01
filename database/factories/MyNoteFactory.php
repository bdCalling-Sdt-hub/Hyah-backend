<?php

namespace Database\Factories;

use App\Models\User;
use Illuminate\Support\Arr;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\MyNote>
 */
class MyNoteFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        $users=User::where('role','USER')->pluck('id')->toArray();
        return [
           'user_id'=>Arr::random($users),
           'note'=>$this->faker->paragraph(2)
        ];
    }
}
