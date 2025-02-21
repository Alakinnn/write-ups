In addition to getting copies of the SAM database to dump and crack hashes, we will also benefit from targeting LSASS. As discussed in the `Credential Storage` section of this module, LSASS is a critical service that plays a central role in credential management and the authentication processes in all Windows operating systems.

![lsass Diagram](https://academy.hackthebox.com/storage/modules/147/lsassexe_diagram.png)
Upon initial logon, LSASS will:

- Cache credentials locally in memory
- Create [access tokens](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- Enforce security policies
- Write to Windows [security log](https://docs.microsoft.com/en-us/windows/win32/eventlog/event-logging-security)

Let's cover some of the techniques and tools we can use to dump LSASS memory and extract credentials from a target running Windows.

---

## Dumping LSASS Process Memory

Similar to the process of attacking the SAM database, with LSASS, it would be wise for us first to create a copy of the contents of LSASS process memory via the generation of a memory dump.

#### Task Manager Method

With access to an interactive graphical session with the target, we can use task manager to create a memory dump. This requires us to:

![Task Manager Memory Dump](https://academy.hackthebox.com/storage/modules/147/taskmanagerdump.png)

`Open Task Manager` > `Select the Processes tab` > `Find & right click the Local Security Authority Process` > `Select Create dump file`

A file called `lsass.DMP` is created and saved in:


```cmd-session
C:\Users\loggedonusersdirectory\AppData\Local\Temp
```

This is the file we will transfer to our attack host. We can use the file transfer method discussed in the `Attacking SAM` section of this module to transfer the dump file to our attack host.

