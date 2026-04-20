package model

type FileStat struct {
	Path  string `json:"path"`
	Opens int64  `json:"opens"`
	Bytes int64  `json:"bytes"`
}

type NetworkStat struct {
	Proto     string `json:"proto"`
	Peer      string `json:"peer"`
	Connects  int64  `json:"connects"`
	Accepts   int64  `json:"accepts"`
	SendCalls int64  `json:"send_calls"`
	RecvCalls int64  `json:"recv_calls"`
	SendBytes int64  `json:"send_bytes"`
	RecvBytes int64  `json:"recv_bytes"`
	Errors    int64  `json:"errors"`
}

type LockStat struct {
	Op       string `json:"op"`
	Count    int64  `json:"count"`
	Errors   int64  `json:"errors"`
	Timeouts int64  `json:"timeouts"`
	TimeNS   int64  `json:"time_ns"`
}

type ErrorStat struct {
	Syscall string `json:"syscall"`
	Errno   string `json:"errno"`
	Target  string `json:"target"`
	Count   int64  `json:"count"`
}

type ProcessStat struct {
	Execs       map[string]int64 `json:"execs"`
	Spawns      map[string]int64 `json:"spawns"`
	ParentSpawn map[int]int64    `json:"parent_spawn"`
	WaitCalls   int64            `json:"wait_calls"`
	ExitCalls   int64            `json:"exit_calls"`
}

type MetadataStat struct {
	Syscall string `json:"syscall"`
	Group   string `json:"group"`
	Count   int64  `json:"count"`
	Fail    int64  `json:"fail"`
}

type PollStat struct {
	Syscall string `json:"syscall"`
	Count   int64  `json:"count"`
	Ready   int64  `json:"ready"`
	Timeout int64  `json:"timeout"`
	Errors  int64  `json:"errors"`
	TimeNS  int64  `json:"time_ns"`
}

type MemoryStat struct {
	Op    string `json:"op"`
	Count int64  `json:"count"`
	Bytes int64  `json:"bytes"`
}

type IPCStat struct {
	Kind       string `json:"kind"`
	Endpoint   string `json:"endpoint"`
	Events     int64  `json:"events"`
	ReadBytes  int64  `json:"read_bytes"`
	WriteBytes int64  `json:"write_bytes"`
}

type Report struct {
	ParsedFiles int `json:"parsed_files"`

	Files    map[string]*FileStat     `json:"files"`
	Network  map[string]*NetworkStat  `json:"network"`
	Locks    map[string]*LockStat     `json:"locks"`
	Errors   map[string]*ErrorStat    `json:"errors"`
	Process  ProcessStat              `json:"process"`
	Metadata map[string]*MetadataStat `json:"metadata"`
	Poll     map[string]*PollStat     `json:"poll"`
	Memory   map[string]*MemoryStat   `json:"memory"`
	IPC      map[string]*IPCStat      `json:"ipc"`
}

func NewReport() *Report {
	return &Report{
		Files:   make(map[string]*FileStat, 4096),
		Network: make(map[string]*NetworkStat, 512),
		Locks:   make(map[string]*LockStat, 64),
		Errors:  make(map[string]*ErrorStat, 256),
		Process: ProcessStat{
			Execs:       make(map[string]int64, 256),
			Spawns:      make(map[string]int64, 16),
			ParentSpawn: make(map[int]int64, 256),
		},
		Metadata: make(map[string]*MetadataStat, 512),
		Poll:     make(map[string]*PollStat, 32),
		Memory:   make(map[string]*MemoryStat, 32),
		IPC:      make(map[string]*IPCStat, 64),
	}
}
