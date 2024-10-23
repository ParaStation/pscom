# Runtime Configuration Options

The `pscom_info` tool can be used to print the runtime configuration options of `pscom`, their default values, and their current settings on your system.
Run the following command (after sucessful installation of `pscom`):

```console
$ pscom_info -c -d
```

## General options

| Option                    | Description         |
|---------------------------|---------------------|
| `PSP_TCP_BACKLOG`         | The TCP backlog of the listening socket. |
| `PSP_UNEXPECTED_RECEIVES` | Enabled/disable receive from connections without outstanding receive requests. |
| `PSP_SCHED_YIELD`         | Schedule with `sched_yield()` instead of busy polling. |
| `PSP_SIGQUIT`             | Debug output on signal `SIGQUIT`. |
| `PSP_SIGSUSPEND`          | Signal number to listen on for connection suspend. |
| `PSP_SIGSEGV`             | Dump stack backtrace on `SIGSEGV`. |
| `PSP_READAHEAD`           | Size of the connections' readahead buffer in byte. |
| `PSP_RETRY`               | Retry counter for `connect()` calls. |
| `PSP_SHUTDOWN_TIMEOUT`    | Timeout value in seconds after which the attempt to close all connections of a socket is aborted if there is no more progress. <br> A timeout value of 0 means an infinite timeout. |
| `PSP_GUARD`               | Enable/disable the connection guards for the detection of failing peer processes. |
| `PSP_IPROBE_COUNT`        | Number of iterations that `pscom_iprobe()` will iterate without progess. |
| `PSP_NETWORK`             | Chose a network (i.e., netmask) for TCP communication. |
| `PSP_PLUGINDIR`           | The path where to find pscom plugins to be loaded. |


## Debug options
| Option              | Description         |
|---------------------|---------------------|
| `PSP_DEBUG_OUT`     | Debug file name with shell-like expansion of the value (`wordexp(8)`). (e.g., `'log_${PMI_RANK}_$$'`) |
| `PSP_DEBUG`         | Logging level defining which messages will be printed:<br> `PSP_DEBUG=0` only fatal conditions (like detected bugs) <br> `PSP_DEBUG=1` fatal conditions + errors (default) <br> `PSP_DEBUG=2` + warnings <br> `PSP_DEBUG=3` + information <br> `PSP_DEBUG=4` + debug <br>  `PSP_DEBUG=5` + verbose debug <br>  `PSP_DEBUG=6` + tracing calls |
| `PSP_DEBUG_REQ`     | Manage a list of all requests for debug dumps. This has a performance impact if enabled. |
| `PSP_DEBUG_TIMING`  | Optional debug output with timing: <table>  <tbody>  <tr> <td> `0`/`(null)` </td> <td> off (default) </td> </tr> <tr> <td> `1`/`'us'` </td> <td> `'ssss.uuuuuu'` seconds and microseconds since `pscom_init` </td> </tr> <tr> <td> `'date'` </td> <td> `'YYYY-MM-DD_hh:mm:ss.uuuuuu'` in localtime </td> </tr> <tr> <td> `'wall'` </td> <td> `'ssss.uuuuuu'` seconds and microseconds since the Epoch </td> </tr> <tr> <td>`'delta'` </td> <td> `'ssss.uuuuuu'` seconds and microseconds since last log </td> </tr> </tbody> </table> |
| `PSP_DEBUG_VERSION` | Always show the pscom version string. |
| `PSP_DEBUG_STATS`   | Collect and print statistics on exit. |
| `PSP_DEBUG_BYE_MSG` | Show the notorious "Byee" message at the end. |
| `PSP_DEBUG_CONTYPE` | Show the connection types being used. |
| `PSP_DEBUG_SUSPEND` | Show suspend information (possible values: 1 or 2). |
| `PSP_DEBUG_PARAM`   | Show the available configuration parameters: <br> `1`: Only show parameters affected by the environment <br> `2`: Show all configuration parameters (available during runtime)  |
| `PSP_DEBUG_PRECON`  | Trace the pre-connection handshake. |
| `PSP_INFO`          | Info logging (requires `libpslib`) |

## CUDA options
*For these options `pscom` has to be compiled with CUDA support.*
| Option                     | Description         |
|----------------------------|---------------------|
| `PSP_CUDA`                 | Enable/ disable CUDA awareness. |
| `PSP_CUDA_SYNC_MEMOPS`     | Enforce synchronization of memory operations on device buffers (important for GPUDirect). |
| `PSP_CUDA_ENFORCE_STAGING` | Enable/Disable the CUDA awareness on the plugin-level, i.e., enforce a pscom-internal staging. |
| `PSP_CUDA_AWARE_SHM`       | Enable/Disable the CUDA awareness of the pscom4shm plugin. |
| `PSP_CUDA_AWARE_OPENIB`    | Enable/Disable the CUDA awareness of the pscom4openib plugin. |
| `PSP_CUDA_AWARE_UCP`       | Enable/Disable the CUDA awareness of the pscom4ucp plugin. |
| `PSP_CUDA_AWARE_VELO`      | Enable/Disable the CUDA awareness of the pscom4velo plugin. |
| `PSP_CUDA_AWARE_EXTOLL`    | Enable/Disable the CUDA awareness of the pscom4extoll plugin. |

## Plugin options

### Customizing plugin priority
By default, `pscom` comes with an internal prioritization of plugins that is used during runtime.
If you want to customize the plugin priorities for your use case you can configure a 'user priority' per plugin using the environment variable `PSP_<arch>` where `<arch>` is the name of the plugin (see list below).
Setting this environment variable to `0` disables a plugin.
Setting a number larger than `0` configures the plugin's priority and overwrites the default priority.
Plugins are sorted first by 'user priority' and second by their internal priority, i.e., equal user priorities lead to a sorting by internal priotities.


| Option        | Description         |
|---------------|---------------------|
| `PSP_TCP`     | The user priority of the pscom4tcp plugin. |
| `PSP_SHM`     | The user priority of the pscom4shm plugin. |
| `PSP_GATEWAY` | The user priority of the pscom4gateway plugin. |
| `PSP_DAPL`    | The user priority of the pscom4dapl plugin. |
| `PSP_ELAN`    | The user priority of the pscom4elan plugin. |
| `PSP_EXTOLL`  | The user priority of the pscom4extoll plugin. This is mutually with pscom4velo (pscom4velo has precedence over pscom4extoll). |
| `PSP_MXM`     | The user priority of the pscom4mxm plugin. |
| `PSP_OFED`    | The user priority of the pscom4ofed plugin. |
| `PSP_MVAPI`   | The user priority of the pscom4mvapi plugin. |
| `PSP_GM`      | The user priority of the pscom4gm plugin. |
| `PSP_OPENIB`  | The user priority of the pscom4open plugin. |
| `PSP_PSM`     | The user priority of the pscom4psm plugin. |
| `PSP_UCP`     | The user priority of the pscom4ucp plugin.|
| `PSP_PORTALS` | The user priority of the pscom4portals plugin.|
| `PSP_VELO`    | The user priority of the pscom4velo plugin. This is mutually with pscom4extoll (pscom4velo has precedence over pscom4extoll). |

### Customizing rendezvous thresholds
If you want to customize rendezvous thresholds of plugins you can set the environment variable `PSP_<arch>_RENDEZVOUS` where `<arch>` is the name of the plugin (see list below).
A value of `inf` disables the rendezvous protocol while enforcing eager communication for the respective plugin.
All rendezvous environment variables inherit from the global rendezvous threshold `PSP_RENDEZVOUS`, i.e., if they are not set explicitly on plugin level, the value of `PSP_RENDEZVOUS` is used instead as rendezvous threshold (if `PSP_RENDEZVOUS` is set).
If none of the rendezvous environment variables are set (neither on plugin nor on global level), the default values from the table below are used as rendezvous thresholds.


| Option                   | Description         |
|--------------------------|---------------------|
| `PSP_RENDEZVOUS`         | The global rendezvous threshold (may be overwritten by plugin-specific configuration). |
| `PSP_SHM_RENDEZVOUS`     | The rendezvous threshold for pscom4shm |
| `PSP_DAPL_RENDEZVOUS`    | The rendezvous threshold for pscom4dapl |
| `PSP_ELAN_RENDEZVOUS`    | The rendezvous threshold for pscom4elan |
| `PSP_EXTOLL_RENDEZVOUS`  | The rendezvous threshold for pscom4extoll |
| `PSP_OPENIB_RENDEZVOUS`  | The rendezvous threshold for pscom4obenib |
| `PSP_UCP_RENDEZVOUS`     | The rendezvous threshold for pscom4ucp |
| `PSP_PORTALS_RENDEZVOUS` | The rendezvous threshold for pscom4portals |
| `PSP_VELO_RENDEZVOUS`    | The rendezvous threshold for pscom4velo |


### Precon options (TCP plugin)
| Option                               | Description         |
|--------------------------------------|---------------------|
| `PSP_PRECON_TCP_SO_SNDBUF`           | The `SO_SNDBUF` size of the precon/TCP connections. |
| `PSP_PRECON_TCP_SO_RCVBUF`           | The `SO_RCVBUF` size of the precon/TCP connections. |
| `PSP_PRECON_TCP_NODELAY`             | Enable/disable `TCP_NODELAY` for the precon/TCP connections. |
| `PSP_PRECON_TCP_RECONNECT_TIMEOUT`   | The reconnect timeout for the precon in milliseconds. |
| `PSP_PRECON_TCP_CONNECT_STALLED_MAX` | Declare after `(`PSP_CONNECT_STALLED` * `PSP_RECONNECT_TIMEOUT`)[ms]` without any received bytes the `connect()` as failed. Retry.  |

### OpenIB plugin options
| Option                            | Description         |
|-----------------------------------|---------------------|
| `PSP_OPENIB_HCA`                  | Name of the HCA to use. |
| `PSP_OPENIB_PORT`                 | Port to use |
| `PSP_OPENIB_PATH_MTU`             | Maximum transmission unit of the IB packets (1:256, 2:512, 3:1024) |
| `PSP_OPENIB_SENDQ_SIZE`           | Number of send buffers per connection |
| `PSP_OPENIB_RECVQ_SIZE`           | Number of receive buffers per connection |
| `PSP_OPENIB_COMPQ_SIZE`           | Size of the completion queue. This likewise corresponds to the size of the global send queue (if enabled) |
| `PSP_OPENIB_GLOBAL_SENDQ`         | Enable/disable global send queue |
| `PSP_OPENIB_EVENT_CNT`            | Enable/disable busy polling if `outstanding_cq_entries` is to high. |
| `PSP_OPENIB_PENDING_TOKENS`       | Number of tokens for incoming packets |
| `PSP_OPENIB_LID_OFFSET`           | Offset to base LID (adaptive routing) |
| `PSP_OPENIB_IGNORE_WRONG_OPCODES` | If enabled, terminate all IB connections when receiving a wrong CQ opcode |
| `PSP_OPENIB_RNDV_FALLBACKS`       | Enable/disable usage of eager/sw-rndv if memory cannot be registered for rendezvous communication. |
| `PSP_OPENIB_MCACHE_SIZE`          | Maximum number of entries in the memory registration cache. Disables the cache if set to 0. |
| `PSP_OPENIB_MALLOC_OPTS`          | Enable/disable the usage of `mallopt()` in the pscom4openib RNDV case. |

### OFED plugin options
| Option                          | Description         |
|---------------------------------|---------------------|
| `PSP_OFED_HCA`                  | Name of the HCA to use. |
| `PSP_OFED_PORT`                 | Port to use |
| `PSP_OFED_PATH_MTU`             | Maximum transmission unit of the IB packets (1:256, 2:512, 3:1024) |
| `PSP_OFED_SENDQ_SIZE`           | Number of send buffers per connection |
| `PSP_OFED_RECVQ_SIZE`           | Number of receive buffers per connection |
| `PSP_OFED_COMPQ_SIZE`           | Size of the completion queue. This likewise corresponds to the size of the global send queue (if enabled) |
| `PSP_OFED_EVENT_CNT`            | Enable/disable busy polling if `outstanding_cq_entries` is to high. |
| `PSP_OFED_PENDING_TOKENS`       | Number of tokens for incoming packets |
| `PSP_OFED_LID_OFFSET`           | Offset to base LID (adaptive routing) |
| `PSP_OFED_WINSIZE`              | Maximum number of unacked packets |
| `PSP_OFED_RESEND_TIMEOUT`       | Resend in usec. 4 times the timeout on each resend starting with `psofed_resend_timeout` maximal wait: 10000 << 11 =  20.48 sec |
| `PSP_OFED_RESEND_TIMEOUT_SHIFT` | Never wait longer than: `psofed_resend_timeout << psofed_resend_timeout_shift` |

### Extoll and Velo plugin options
| Option                      | Description         |
|-----------------------------|---------------------|
| `PSP_EXTOLL_SENDQ_SIZE`     | Number of send buffers per connection |
| `PSP_EXTOLL_RECVQ_SIZE`     | Number of receive buffers per connection |
| `PSP_EXTOLL_GLOBAL_SENDQ`   | Enable/disable global send queue |
| `PSP_EXTOLL_EVENT_CNT`      | Enable/disable busy polling if `psex_pending_global_sends` is to high. |
| `PSP_EXTOLL_PENDING_TOKENS` | Number of tokens for incoming packets |
| `PSP_EXTOLL_MCACHE_SIZE`    | For Velo only: Maximum number of entries in the memory registration cache. Minimum 1, i.e., cannot be disabled at runtime |

### PSM plugin options
| Option                | Description         |
|-----------------------|---------------------|
| `PSP_PSM_FASTINIT`    | If enabled, `psm2_init()` is called from within pscom4psm plugin init, otherwise on first usage of a pscom4psm connection. |
| `PSP_PSM_CLOSE_DELAY` | Delayed call to `psm2_ep_disconnect2()` in milliseconds. |
| `PSP_PSM_UNIQ_ID`     | Unsigned integer used to seed the PSM UUID. If unset or zero, PMI_ID is checked. If also unset or zero, a constant seed is used. |
| `PSP_PSM_DEVCHECK`    | Enable/disable checking for any of the following device files: `/dev/ipath{,0,1}`,`/dev/hfi{1,2}{,_0,_1,_2}` |

### UCP plugin options
| Option                  | Description         |
|-------------------------|---------------------|
| `PSP_UCP_FASTINIT`      | If enabled, `ucp_init()` is called from within pscom4ucp plugin init, otherwise on first usage of a pscom4ucp connection. |
| `PSP_UCP_MAX_RECV`      | Limit the number of outstanding receive requests that are handled by the pscom4ucp plugin concurrently. |
| `PSP_UCP_SMALL_MSG_LEN` | The threshold for buffered sending of small messages |

### MXM plugin options
| Option             | Description         |
|--------------------|---------------------|
| `PSP_MXM_DEVCHECK` | Enable/disable checking for any of the following device files: `/sys/class/infiniband/mlx5_{0,1,2}` |

### Portals plugin options
| Option                           | Description         |
|----------------------------------|---------------------|
| `PSP_PORTALS_BUFFER_SIZE`        | The size of the buffers in the send/recv queues. |
| `PSP_PORTALS_RECVQ_SIZE`         | Number of receive buffers per connection. |
| `PSP_PORTALS_SENDQ_SIZE`         | Number of send buffers per connection. |
| `PSP_PORTALS_EQ_SIZE`            | Size of the event queue. |
| `PSP_PORTALS_FOSTER_PROGRESS`    | Make additional progress on the completion of send operations (when relying on SWPTL this may be required). |
| `PSP_PORTALS_MAX_RNDV_REQS`      | Maximum number of outstanding rendezvous requests per connection. |
| `PSP_PORTALS_RNDV_FRAGMENT_SIZE` | Maximum size of the fragments being sent during rendezvous communication. This is limited by the maximum message size supported by the NI. |
