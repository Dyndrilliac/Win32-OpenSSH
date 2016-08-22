#include <Windows.h>
#include "w32fd.h"
#include "tncon.h"
#include "inc/defs.h"

#define TERM_IO_BUF_SIZE 2048

struct io_status {
	DWORD to_transfer;
	DWORD transferred;
	DWORD error;
};

static struct io_status read_status, write_status;

static VOID CALLBACK ReadAPCProc(
	_In_ ULONG_PTR dwParam
	) {
	struct w32_io* pio = (struct w32_io*)dwParam;
	debug3("TermRead CB - io:%p, bytes: %d, pending: %d, error: %d", pio, read_status.transferred,
		pio->read_details.pending, read_status.error);
	pio->read_details.error = read_status.error;
	pio->read_details.remaining = read_status.transferred;
	pio->read_details.completed = 0;
	pio->read_details.pending = FALSE;
	WaitForSingleObject(pio->read_overlapped.hEvent, INFINITE);
	CloseHandle(pio->read_overlapped.hEvent);
	pio->read_overlapped.hEvent = 0;
}

static DWORD WINAPI ReadThread(
    _In_ LPVOID lpParameter
) {
    struct w32_io* pio = (struct w32_io*)lpParameter;
    debug3("TermRead thread, io:%p", pio);
    memset(&read_status, 0, sizeof(read_status));
    if (!ReadFile(WINHANDLE(pio), pio->read_details.buf,
        pio->read_details.buf_size, &read_status.transferred, NULL)) {
        read_status.error = GetLastError();
        debug("TermRead thread - ReadFile failed %d, io:%p", GetLastError(), pio);
    }

    if (0 == QueueUserAPC(ReadAPCProc, main_thread, (ULONG_PTR)pio)) {
        debug("TermRead thread - ERROR QueueUserAPC failed %d, io:%p", GetLastError(), pio);
        pio->read_details.pending = FALSE;
        pio->read_details.error = GetLastError();
        DebugBreak();
    }
    return 0;
}

static DWORD WINAPI ReadConsoleThread(
    _In_ LPVOID lpParameter
) {
    int nBytesReturned = 0;

    struct w32_io* pio = (struct w32_io*)lpParameter;

    debug3("TermRead thread, io:%p", pio);
    memset(&read_status, 0, sizeof(read_status));
   
    while (nBytesReturned == 0) {
        nBytesReturned = ReadConsoleForTermEmul(WINHANDLE(pio),
            pio->read_details.buf, pio->read_details.buf_size);
    }

    read_status.transferred = nBytesReturned;

    if (0 == QueueUserAPC(ReadAPCProc, main_thread, (ULONG_PTR)pio)) {
        debug("TermRead thread - ERROR QueueUserAPC failed %d, io:%p", GetLastError(), pio);
        pio->read_details.pending = FALSE;
        pio->read_details.error = GetLastError();
        DebugBreak();
    }

    return 0;
}

static VOID CALLBACK
ReadAsyncAPCProc(
    _In_ ULONG_PTR dwParam
) {
    struct w32_io* pio = (struct w32_io*)dwParam;

    debug3("TermRead ReadAsyncAPCProc CB - io:%p, bytes: %d, pending: %d, error: %d", pio, read_status.transferred,
        pio->read_details.pending, read_status.error);
    pio->read_details.error = read_status.error;
    pio->read_details.remaining = read_status.transferred;
    pio->read_details.completed = 0;
    pio->read_details.pending = FALSE;
    CloseHandle(pio->read_overlapped.hEvent);
    pio->read_overlapped.hEvent = 0;
}

static DWORD WINAPI
ReadAsyncThread(
    _In_ LPVOID lpParameter
) {
    struct w32_io* pio = (struct w32_io*)lpParameter;

    DWORD dwStatus = 0;
    BOOL bResult = FALSE;
    BOOL bContinue = TRUE;

    read_status.error = 0;
    read_status.to_transfer = 0;
    read_status.transferred = 0;

    debug3("TermRead thread, io:%p", pio);
    while (bContinue)
    {
        bContinue = FALSE;

        if (!ReadFile(WINHANDLE(pio), pio->read_details.buf, pio->read_details.buf_size,
                &read_status.transferred, &pio->read_overlapped)) {
            read_status.error = GetLastError();
                switch (read_status.error) {
                case ERROR_HANDLE_EOF:
                {
                    debug2("TermIO ReadAsyncThread ERROR_HANDLE_EOF 1 CB - io:%p, bytes: %d, pending: %d, error: %d", pio, read_status.transferred,
                        pio->read_details.pending, read_status.error);

                    break;
                }
                case ERROR_IO_PENDING:
                {
                    BOOL bPending = TRUE;

                    while (bPending)
                    {
                        bPending = FALSE;

                        WaitForSingleObject(pio->read_overlapped.hEvent, INFINITE);

                        bResult = GetOverlappedResult(WINHANDLE(pio),
                            &pio->read_overlapped, &read_status.transferred, FALSE);

                        if (!bResult)
                        {
                            read_status.error = GetLastError();
                            switch (read_status.error)
                            {
                                case ERROR_HANDLE_EOF:
                                {
                                    bPending = FALSE;
                                    bContinue = FALSE;
                                    if(read_status.transferred > 0)
                                        read_status.error = 0;

                                    debug2("TermIO ReadAsyncThread: io:%p, bytes: %d, pending: %d, error: %d ERROR_HANDLE_EOF", pio, read_status.transferred,
                                        pio->read_details.pending, read_status.error);
                                    break;
                                }
                                case ERROR_IO_INCOMPLETE:
                                {
                                    bPending = TRUE;
                                    bContinue = TRUE;

                                    debug2("TermIO ReadAsyncThread: io:%p, bytes: %d, pending: %d, error: %d ERROR_IO_INCOMPLETE", pio, read_status.transferred,
                                        pio->read_details.pending, read_status.error);
                                    break;
                                }
                                case ERROR_BROKEN_PIPE:
                                {
                                    bPending = FALSE;
                                    bContinue = FALSE;
                                    read_status.error = ERROR_BROKEN_PIPE;

                                    debug2("TermIO ReadAsyncThread: io:%p, bytes: %d, pending: %d, error: %d ERROR_BROKEN_PIPE", pio, read_status.transferred,
                                        pio->read_details.pending, read_status.error);
                                    break;
                                }
                                default:
                                {
                                    debug2("TermIO ReadAsyncThread: io:%p, bytes: %d, pending: %d, error: %d", pio, read_status.transferred,
                                        pio->read_details.pending, read_status.error);

                                    break;
                                }
                            }
                        }
                        else
                        {
                            read_status.error = 0;
                        }
                    }
                    break;
                }
                default:
                {
                    debug2("TermIO ReadAsyncThread: io:%p, bytes: %d, pending: %d, error: %d", pio, read_status.transferred,
                        pio->read_details.pending, read_status.error);

                    break;
                }
            }

            LARGE_INTEGER quad;
            quad.HighPart = pio->read_overlapped.OffsetHigh;
            quad.LowPart = pio->read_overlapped.Offset;

            quad.QuadPart = quad.QuadPart + read_status.transferred;
            pio->read_overlapped.OffsetHigh = quad.HighPart;
            pio->read_overlapped.Offset = quad.LowPart;
        }
        else
        {
            debug2("TermIO ReadAsyncThread: io:%p, bytes: %d, pending: %d, error: %d", pio, read_status.transferred,
                pio->read_details.pending, read_status.error);
        }
    }

    if (0 == QueueUserAPC(ReadAsyncAPCProc, main_thread, (ULONG_PTR)pio)) {
        debug("TermAsyncRead thread - ERROR QueueUserAPC failed %d, io:%p", GetLastError(), pio);
        pio->read_details.pending = FALSE;
        DebugBreak();
    }
    return dwStatus;
}

int
termio_initiate_read(struct w32_io* pio, BOOL bAsync) {
	HANDLE read_thread;

	debug3("TermRead initiate io:%p", pio);

	if (pio->read_details.buf_size == 0) {
		pio->read_details.buf = malloc(TERM_IO_BUF_SIZE);
		if (pio->read_details.buf == NULL) {
			errno = ENOMEM;
			return -1;
		}
		pio->read_details.buf_size = TERM_IO_BUF_SIZE;
	}

    if (bAsync) {
        pio->read_overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        read_thread = CreateThread(NULL, 0, ReadAsyncThread, pio, CREATE_SUSPENDED, NULL);
    }
    else 
        read_thread = CreateThread(NULL, 0, ReadConsoleThread, pio, CREATE_SUSPENDED, NULL);

	if (read_thread == NULL) {
		errno = errno_from_Win32Error(GetLastError());
		debug("TermRead initiate - ERROR CreateThread %d, io:%p", GetLastError(), pio);
		return -1;
	}

    if (!bAsync)
        pio->read_overlapped.hEvent = read_thread;
	pio->read_details.pending = TRUE;
    ResumeThread(read_thread);
	return 0;
}

static VOID CALLBACK 
WriteAPCProc(
	_In_ ULONG_PTR dwParam
	) {
	struct w32_io* pio = (struct w32_io*)dwParam;
	debug3("TermWrite CB - io:%p, bytes: %d, pending: %d, error: %d", pio, write_status.transferred,
		pio->write_details.pending, write_status.error);
	pio->write_details.error = write_status.error;
	pio->write_details.remaining -= write_status.transferred;
	/*TODO- assert that reamining is 0 by now*/
	pio->write_details.completed = 0;
	pio->write_details.pending = FALSE;
	WaitForSingleObject(pio->write_overlapped.hEvent, INFINITE);
	CloseHandle(pio->write_overlapped.hEvent);
	pio->write_overlapped.hEvent = 0;
}

static VOID CALLBACK
WriteAsyncAPCProc(
    _In_ ULONG_PTR dwParam
) {
    struct w32_io* pio = (struct w32_io*)dwParam;

    debug3("TermWrite CB - io:%p, bytes: %d, pending: %d, error: %d", pio, write_status.transferred,
        pio->write_details.pending, write_status.error);
    pio->write_details.error = write_status.error;
    pio->write_details.remaining -= write_status.transferred;
    /*TODO- assert that remaining is 0 by now*/
    pio->write_details.completed = 0;
    pio->write_details.pending = FALSE;
    CloseHandle(pio->write_overlapped.hEvent);
    pio->write_overlapped.hEvent = 0;
}

static DWORD WINAPI
WriteAsyncThread(
    _In_ LPVOID lpParameter
) {
    struct w32_io* pio = (struct w32_io*)lpParameter;

    // Always write to the end (if offsets are used).
    pio->write_overlapped.Offset = 0xFFFFFFFF;
    pio->write_overlapped.OffsetHigh = 0xFFFFFFFF;

    debug3("TermWrite thread, io:%p", pio);
    if (!WriteFile(WINHANDLE(pio), pio->write_details.buf, write_status.to_transfer,
            NULL, &pio->write_overlapped)) {
        write_status.error = GetLastError();
        if (write_status.error == ERROR_IO_PENDING) {

            WaitForSingleObject(pio->write_overlapped.hEvent, 0);

            if (!GetOverlappedResult(WINHANDLE(pio), &pio->write_overlapped,
                &write_status.transferred, TRUE)) {
                debug("TermAsyncWrite thread - GetOverlappedResult failed %d, io:%p", write_status.error, pio);
            }

            write_status.error = 0;
        }
        else {
            debug("TermAsyncWrite thread - WriteFile failed %d, io:%p", write_status.error, pio);
        }
    }
    else {
        if (!GetOverlappedResult(WINHANDLE(pio), &pio->write_overlapped,
            &write_status.transferred, TRUE)) {
            debug("TermAsyncWrite thread - GetOverlappedResult failed %d, io:%p", write_status.error, pio);
        }
    }

    if (0 == QueueUserAPC(WriteAsyncAPCProc, main_thread, (ULONG_PTR)pio)) {
        debug("TermAsyncWrite thread - ERROR QueueUserAPC failed %d, io:%p", GetLastError(), pio);
        pio->write_details.error = GetLastError();
        DebugBreak();
    }
    return 0;
}

static DWORD WINAPI 
WriteThread(
	_In_ LPVOID lpParameter
	) {
	struct w32_io* pio = (struct w32_io*)lpParameter;
	debug3("TermWrite thread, io:%p", pio);
	if (!WriteFile(WINHANDLE(pio), pio->write_details.buf, write_status.to_transfer, 
	    &write_status.transferred, NULL)) {
		write_status.error = GetLastError();
		debug("TermWrite thread - WriteFile failed %d, io:%p", GetLastError(), pio);
	}

	if (0 == QueueUserAPC(WriteAPCProc, main_thread, (ULONG_PTR)pio)) {
		debug("TermWrite thread - ERROR QueueUserAPC failed %d, io:%p", GetLastError(), pio);
		pio->write_details.pending = FALSE;
		pio->write_details.error = GetLastError();
		DebugBreak();
	}
	return 0;
}

int
termio_initiate_write(struct w32_io* pio, DWORD num_bytes, BOOL bAsync) {
	HANDLE write_thread;

	debug3("TermWrite initiate io:%p", pio);
	memset(&write_status, 0, sizeof(write_status));
	write_status.to_transfer = num_bytes;
    if (bAsync) {
        pio->write_overlapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

        write_thread = CreateThread(NULL, 0, WriteAsyncThread, pio, CREATE_SUSPENDED, NULL);
    }
    else {
        write_thread = CreateThread(NULL, 0, WriteThread, pio, CREATE_SUSPENDED, NULL);
    }

    if (write_thread == NULL) {
        if (pio->write_overlapped.hEvent) {
            CloseHandle(pio->write_overlapped.hEvent);
            pio->write_overlapped.hEvent = NULL;
        }
		errno = errno_from_Win32Error(GetLastError());
		debug("TermWrite initiate - ERROR CreateThread %d, io:%p", GetLastError(), pio);
		return -1;
	}

    if (!bAsync)
        pio->write_overlapped.hEvent = write_thread;
	pio->write_details.pending = TRUE;
    ResumeThread(write_thread);
    return 0;
}


int termio_close(struct w32_io* pio) {
	debug2("termio_close - pio:%p", pio);
	HANDLE h;

	CancelIoEx(WINHANDLE(pio), NULL);
	/* If io is pending, let write worker threads exit. The read thread is blocked so terminate it.*/
    if (pio->read_details.pending)
        TerminateThread(pio->read_overlapped.hEvent, 0);
	if (pio->write_details.pending)
		WaitForSingleObject(pio->write_overlapped.hEvent, INFINITE);
	/* drain queued APCs */
	SleepEx(0, TRUE);
	if (pio->type != STD_IO_FD) {//STD handles are never explicitly closed
		CloseHandle(WINHANDLE(pio));

		if (pio->read_details.buf)
			free(pio->read_details.buf);

		if (pio->write_details.buf)
			free(pio->write_details.buf);

		free(pio);
	}
	return 0;
}
