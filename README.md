# Laravel 11 JWT Authentication API Setup

## How to Setup
Follow the installation steps below to set up JWT Authentication.

### Installation Steps

#### Step 1: Clone the Repository
Copy this link and paste it into your local web server:
```bash
git clone https://github.com/Sazzat-UGV/JWT-Authentication.git
```
Change directory to your project:
```bash
cd JWT-Authentication
```

#### Step 2: Update Composer
Install or update project dependencies:
```bash
composer update
```

#### Step 3: Create .env File
Copy the `.env.example` file to `.env`:
```bash
cp .env.example .env
```

#### Step 4: Generate Application Key
Generate the application key:
```bash
php artisan key:generate
```

#### Step 5: Generate JWT Secret Key
Generate the JWT secret key:
```bash
php artisan jwt:secret
```

#### Step 6: Run the Application
Run migrations:
```bash
php artisan migrate
```
Start the server:
```bash
php artisan serve
```
