<?php
namespace App\Http\Controllers\api\Frontend;

use App\Http\Controllers\Controller;
use App\Models\MyNote;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;

class MyNoteController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        //
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'note' => 'required|string',
        ]);
        if ($validator->fails()) {
            return response()->json([
                'status'  => false,
                'message' => $validator->errors(),
            ], 400);
        }
        $data = MyNote::create([
            'user_id' => Auth::id(),
            'note'    => $request->note,
        ]);
        return response([
            'status'  => true,
            'message' => 'Note added successfully.',
            'data'    => $data,
        ]);
    }

    /**
     * Display the specified resource.
     */
    public function show(string $id)
    {
        //
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit(string $id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, $id)
    {
        $validator = Validator::make($request->all(), [
            'note' => 'required|string',
        ]);
        if ($validator->fails()) {
            return response()->json([
                'status'  => false,
                'message' => $validator->errors(),
            ], 400);
        }
        try {
            $note       = MyNote::findOrFail($id);
            $note->note = $request->note;
            $note->save();
            return response([
                'status'  => true,
                'message' => 'Note updated successfully.',
                'data'    => $note,
            ]);
        } catch (Exception $e) {
            Log::error('Note updated error: ' . $e->getMessage());
            return response([
                'status'  => false,
                'message' => 'No data found.',
                'data'    => null,
            ]);
        }
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(string $id)
    {
        try {
            $data = MyNote::findOrFail($id);
            $data->delete();
            return response([
                'status'  => true,
                'message' => 'Note deleted successfully.',
                'data'    => $data,
            ]);
        } catch (Exception $e) {
            Log::error('Note delete error: ' . $e->getMessage());
            return response([
                'status'  => false,
                'message' => 'No data found.',
                'data'    => null,
            ]);
        }
    }
}
