#include "Themida.hpp"

#include <Windows.h>
#include <vector>

#include <zasm/decoder/decoder.hpp>
#include <zasm/formatter/formatter.hpp>
#include <zasm/serialization/serializer.hpp>
#include <zasm/zasm.hpp>

#include "PEReader.h"
#include "Utility.h"

namespace Themida {
	void* AllocatedAddr = nullptr;

	void* TextRegionStart = nullptr;
	unsigned int TextRegionSize = 0;

	std::vector<unsigned char> BackUp;
	zasm::Program program( zasm::MachineMode::AMD64 );

	bool Hook_VirtualAlloc()
	{
		static decltype( &VirtualAlloc ) _VirtualAlloc = &VirtualAlloc;

		static auto oVirtualAlloc = _VirtualAlloc;

		static decltype( &VirtualAlloc ) VirtualAlloc_Hook = []( LPVOID lpAddress,
			SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect ) -> LPVOID {
				if ( dwSize != TextRegionSize )
					return _VirtualAlloc( lpAddress, dwSize, flAllocationType, flProtect );
				AllocatedAddr = _VirtualAlloc( lpAddress, dwSize, flAllocationType, flProtect );
				if ( !AllocatedAddr ) return AllocatedAddr;
				memcpy( AllocatedAddr, BackUp.data(), BackUp.size() );

				DWORD oldProtect;
				VirtualProtect( AllocatedAddr, dwSize, PAGE_READONLY, &oldProtect );

				return AllocatedAddr;
			};
		return Utility::CreateHook( reinterpret_cast<void**>( &_VirtualAlloc ), VirtualAlloc_Hook, oVirtualAlloc, true );
	}

	LONG CALLBACK VectoredHandler( PEXCEPTION_POINTERS ExceptionInfo )
	{
		if ( ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
			ExceptionInfo->ContextRecord->Rdi == (__int64)AllocatedAddr ) {
			zasm::Instruction i( ExceptionInfo->ContextRecord->Rip );
			if ( i.getDetail( zasm::MachineMode::AMD64 ) ) {
				ExceptionInfo->ContextRecord->Rip += 2;
			}
			else {
				ExceptionInfo->ContextRecord->Rip += i.getDetail( zasm::MachineMode::AMD64 ).value().getLength();
			}
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		return EXCEPTION_CONTINUE_SEARCH;
	}

	bool AddVEH()
	{
		return AddVectoredExceptionHandler( 1, &VectoredHandler ) != NULL;
	}

	bool InitialiseCRCBypass()
	{
		PEReader pe( GetModuleHandleA( NULL ), true );
		pe.for_each_section( [&]( PIMAGE_SECTION_HEADER p ) {
			if ( !strstr( (char*)p->Name, ".text" ) ) return;
			TextRegionSize = p->SizeOfRawData;
			TextRegionStart = reinterpret_cast<unsigned char*>( pe.get_start() ) + p->VirtualAddress;
			} );
		if ( !TextRegionStart || !TextRegionSize )
			return false;
		BackUp.resize( TextRegionSize );
		memcpy( BackUp.data(), TextRegionStart, TextRegionSize );

		return AddVEH() && Hook_VirtualAlloc();
	}
}
