<?php

namespace Database\Seeders;

use App\Models\MyNote;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

class MyNoteSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        MyNote::factory()->count(1)->create();
    }
}
