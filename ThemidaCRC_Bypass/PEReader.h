#pragma once
#include <Windows.h>

class PEReader {
public:
	PEReader( HMODULE module_handle, bool is_x64 )
		: m_base( reinterpret_cast<LPBYTE>( module_handle ) ), m_is_x64( is_x64 ) {
		parseHeaders();
	}

	template<typename Func>
	void for_each_section( Func f ) {
		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION( m_nt_headers );
		for ( int i = 0; i < m_nt_headers->FileHeader.NumberOfSections; ++i, ++section ) {
			f( section );
		}
	}

	LPBYTE get_start() const {
		return m_base;
	}

private:
	LPBYTE m_base;
	bool m_is_x64;
	PIMAGE_NT_HEADERS m_nt_headers;

	void parseHeaders() {
		PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>( m_base );
		m_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>( m_base + dos_header->e_lfanew );
	}
};