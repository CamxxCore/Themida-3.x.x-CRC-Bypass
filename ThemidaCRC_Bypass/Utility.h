#pragma once
#include <Windows.h>
#include <minhook\MinHook.h>

namespace Utility {

	template <typename T>
	int CreateHook( LPVOID pTarget, LPVOID pDetour, T* result, bool enabled = true ) {

		MH_STATUS status = MH_Initialize();

		if ( status && status != MH_ERROR_ALREADY_INITIALIZED )
			return status;

		if ( ( status = MH_CreateHook( pTarget, pDetour,
			reinterpret_cast<LPVOID*>( result ) ) ) != MH_OK ) {
			return status;
		}

		return status ? status : ( enabled ? MH_EnableHook( pTarget ) : status );
	}
};
