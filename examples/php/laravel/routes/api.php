<?php

use App\Http\Controllers\NotesApiController;
use Illuminate\Support\Facades\Route;

// These routes are registered in bootstrap/app.php with an empty prefix, so
// they live at the root (/login, /notes, ...) rather than under /api. They
// use the stateless "api" middleware group: no session, no cookies, no CSRF.

Route::get('/public', [NotesApiController::class, 'public']);

// Forwarded to Keyora with this application's client secret.
Route::post('/register', [NotesApiController::class, 'register']);
Route::post('/login', [NotesApiController::class, 'login']);
Route::post('/refresh', [NotesApiController::class, 'refresh']);
Route::post('/logout', [NotesApiController::class, 'logout']);

// Any valid access token, verified locally.
Route::get('/me', [NotesApiController::class, 'me'])->middleware('keyora.auth');

// Verified by asking Keyora (introspection), inside the controller.
Route::get('/me/live', [NotesApiController::class, 'meLive']);

// Permission-based authorization: all listed permissions are required.
Route::get('/notes', [NotesApiController::class, 'listNotes'])->middleware('keyora.permission:notes:read');
Route::post('/notes', [NotesApiController::class, 'createNote'])->middleware('keyora.permission:notes:write');

// Role-based authorization: any one of the listed roles is enough.
Route::get('/reports', [NotesApiController::class, 'reports'])->middleware('keyora.role:editor');
