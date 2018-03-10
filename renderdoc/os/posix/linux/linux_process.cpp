/******************************************************************************
 * The MIT License (MIT)
 *
 * Copyright (c) 2016-2018 Baldur Karlsson
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 ******************************************************************************/

#include <unistd.h>
#include "os/os_specific.h"

#ifdef __FreeBSD__
#include <netinet/in.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <libprocstat.h>
#endif

extern char **environ;

#define INITIAL_WAIT_TIME 1
#define MAX_WAIT_TIME 128000

char **GetCurrentEnvironment()
{
  return environ;
}

#ifdef __linux__
int GetIdentPort(pid_t childPid)
{
  int ret = 0;

  string procfile = StringFormat::Fmt("/proc/%d/net/tcp", (int)childPid);

  int waitTime = INITIAL_WAIT_TIME;

  // try for a little while for the /proc entry to appear
  while(ret == 0 && waitTime <= MAX_WAIT_TIME)
  {
    // back-off for each retry
    usleep(waitTime);

    waitTime *= 2;

    FILE *f = FileIO::fopen(procfile.c_str(), "r");

    if(f == NULL)
    {
      // try again in a bit
      continue;
    }

    // read through the proc file to check for an open listen socket
    while(ret == 0 && !feof(f))
    {
      const size_t sz = 512;
      char line[sz];
      line[sz - 1] = 0;
      fgets(line, sz - 1, f);

      int socketnum = 0, hexip = 0, hexport = 0;
      int num = sscanf(line, " %d: %x:%x", &socketnum, &hexip, &hexport);

      // find open listen socket on 0.0.0.0:port
      if(num == 3 && hexip == 0 && hexport >= RenderDoc_FirstTargetControlPort &&
         hexport <= RenderDoc_LastTargetControlPort)
      {
        ret = hexport;
      }
    }

    FileIO::fclose(f);
  }

  if(ret == 0)
  {
    RDCWARN("Couldn't locate renderdoc target control listening port between %u and %u in %s",
            (uint32_t)RenderDoc_FirstTargetControlPort, (uint32_t)RenderDoc_LastTargetControlPort,
            procfile.c_str());
  }

  return ret;
}
#elif __FreeBSD__
int GetIdentPort(pid_t childPid)
{
  int ret = 0;
  int waitTime = INITIAL_WAIT_TIME;

  struct procstat *procstat = procstat_open_sysctl();

  struct filestat_list *head = nullptr;
  struct filestat *fst = nullptr;

  unsigned int cnt;
  struct kinfo_proc *kp = procstat_getprocs(procstat, KERN_PROC_PID, childPid, &cnt);
  if(cnt != 1)
  {
    RDCWARN("Matched %d processes for pid %d instead of one", cnt, childPid);
    ret = 0;
    goto fail_procs;
  }


  // try for a little while for the /proc entry to appear
  while(ret == 0 && waitTime <= MAX_WAIT_TIME)
  {
    // back-off for each retry
    usleep(waitTime);

    waitTime *= 2;

    head = procstat_getfiles(procstat, kp, 0);

    if(head == nullptr)
      continue;

    STAILQ_FOREACH(fst, head, next) {
      if(fst->fs_type != PS_FST_TYPE_SOCKET)
        continue;
      struct sockstat sock;
      char errbuf[_POSIX2_LINE_MAX];
      if(procstat_get_socket_info(procstat, fst, &sock, errbuf) < 0)
      {
        RDCWARN("procstat_get_socket_info: %s", errbuf);
        continue;
      }
      if(sock.proto != IPPROTO_TCP)
        continue;
      struct sockaddr_in *isock = reinterpret_cast<struct sockaddr_in*>(&sock.sa_local);
      uint16_t port = ntohs(isock->sin_port);
      if(sock.so_addr == 0 && port >= RenderDoc_FirstTargetControlPort
          && port <= RenderDoc_LastTargetControlPort)
        ret = port;
    }

    procstat_freefiles(procstat, head);
  }
fail_procs:
  procstat_freeprocs(procstat, kp);
  procstat_close(procstat);

  if(ret == 0)
  {
    RDCWARN("Couldn't locate renderdoc target control listening port between %u and %u for pid %d",
            (uint32_t)RenderDoc_FirstTargetControlPort, (uint32_t)RenderDoc_LastTargetControlPort, childPid);
  }

  return ret;
}
#endif

// because OSUtility::DebuggerPresent is called often we want it to be
// cheap. Opening and parsing a file would cause high overhead on each
// call, so instead we just cache it at startup. This fails in the case
// of attaching to processes
bool debuggerPresent = false;

void CacheDebuggerPresent()
{
  FILE *f = FileIO::fopen("/proc/self/status", "r");

  if(f == NULL)
  {
    RDCWARN("Couldn't open /proc/self/status");
    return;
  }

  // read through the proc file to check for TracerPid
  while(!feof(f))
  {
    const size_t sz = 512;
    char line[sz];
    line[sz - 1] = 0;
    fgets(line, sz - 1, f);

    int tracerpid = 0;
    int num = sscanf(line, "TracerPid: %d", &tracerpid);

    // found TracerPid line
    if(num == 1)
    {
      debuggerPresent = (tracerpid != 0);
      break;
    }
  }

  FileIO::fclose(f);
}

bool OSUtility::DebuggerPresent()
{
  return debuggerPresent;
}

const char *Process::GetEnvVariable(const char *name)
{
  return getenv(name);
}
