#include "filesys/fat.h"
#include "devices/disk.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include <stdio.h>
#include <string.h>

/* Should be less than DISK_SECTOR_SIZE */
struct fat_boot {
	unsigned int magic;
	unsigned int sectors_per_cluster; /* Fixed to 1 */
	unsigned int total_sectors;
	unsigned int fat_start;
	unsigned int fat_sectors; /* Size of FAT in sectors. fat가 차지하는 섹터 수 */
	unsigned int root_dir_cluster;
};



/* FAT FS */
struct fat_fs {
	struct fat_boot bs;         /* Boot sector의 내용을 저장하는 구조체. File System에 대한 정보를 세팅한다. */
	unsigned int *fat;          /* PintOS가 부팅되면서 FAT를 Disk에서 읽어오고 메모리에 올리는데, 이때 FAT가 올라간 메모리의 시작 주소 */
	unsigned int fat_length;    /* FAT의 entry 갯수 (FAT에서 관리하는 cluster의 갯수 = Data area의 sector 수) */
	disk_sector_t data_start;   /* Filesys Disk에서 FAT area이후, Data area가 시작되는 첫번째 sector */
	cluster_t last_clst;        /* 추측: FAT의 마지막 클러스터 번호 = data_start - 1 이 될것으로 에상함. (그런데 이걸 굳이 따로 멤버로 저장해두어야 할까?) */
	struct lock write_lock;
};

static struct fat_fs *fat_fs;
static struct cluster_map *cluster_map;

void fat_boot_create (void);
void fat_fs_init (void);
bool fat_alloc_get_multiple(size_t cnt, disk_sector_t *sectorp);
bool fat_alloc_get_clst(disk_sector_t *sectorp);

void
fat_init (void) {
	fat_fs = calloc (1, sizeof (struct fat_fs));
	if (fat_fs == NULL)
		PANIC ("FAT init failed");

	// Read boot sector from the disk
	unsigned int *bounce = malloc (DISK_SECTOR_SIZE);
	if (bounce == NULL)
		PANIC ("FAT init failed");
	disk_read (filesys_disk, FAT_BOOT_SECTOR, bounce);
	memcpy (&fat_fs->bs, bounce, sizeof (fat_fs->bs));
	free (bounce);

	// Extract FAT info
	if (fat_fs->bs.magic != FAT_MAGIC)
		fat_boot_create ();
	fat_fs_init ();
}

void
fat_open (void) {
	fat_fs->fat = calloc (fat_fs->fat_length, sizeof (cluster_t));
	if (fat_fs->fat == NULL)
		PANIC ("FAT load failed");

	// Load FAT directly from the disk
	uint8_t *buffer = (uint8_t *) fat_fs->fat;
	off_t bytes_read = 0;
	off_t bytes_left = sizeof (fat_fs->fat);
	const off_t fat_size_in_bytes = fat_fs->fat_length * sizeof (cluster_t);
	for (unsigned i = 0; i < fat_fs->bs.fat_sectors; i++) {
		bytes_left = fat_size_in_bytes - bytes_read;
		if (bytes_left >= DISK_SECTOR_SIZE) {
			disk_read (filesys_disk, fat_fs->bs.fat_start + i,
			           buffer + bytes_read);
			bytes_read += DISK_SECTOR_SIZE;
		} else {
			uint8_t *bounce = malloc (DISK_SECTOR_SIZE);
			if (bounce == NULL)
				PANIC ("FAT load failed");
			disk_read (filesys_disk, fat_fs->bs.fat_start + i, bounce);
			memcpy (buffer + bytes_read, bounce, bytes_left);
			bytes_read += bytes_left;
			free (bounce);
		}
	}
}

void
fat_close (void) {
	// Write FAT boot sector
	uint8_t *bounce = calloc (1, DISK_SECTOR_SIZE);
	if (bounce == NULL)
		PANIC ("FAT close failed");
	memcpy (bounce, &fat_fs->bs, sizeof (fat_fs->bs));
	disk_write (filesys_disk, FAT_BOOT_SECTOR, bounce);
	free (bounce);

	// Write FAT directly to the disk
	uint8_t *buffer = (uint8_t *) fat_fs->fat;
	off_t bytes_wrote = 0;
	off_t bytes_left = sizeof (fat_fs->fat);
	const off_t fat_size_in_bytes = fat_fs->fat_length * sizeof (cluster_t);
	for (unsigned i = 0; i < fat_fs->bs.fat_sectors; i++) {
		bytes_left = fat_size_in_bytes - bytes_wrote;
		if (bytes_left >= DISK_SECTOR_SIZE) {
			disk_write (filesys_disk, fat_fs->bs.fat_start + i,
			            buffer + bytes_wrote);
			bytes_wrote += DISK_SECTOR_SIZE;
		} else {
			bounce = calloc (1, DISK_SECTOR_SIZE);
			if (bounce == NULL)
				PANIC ("FAT close failed");
			memcpy (bounce, buffer + bytes_wrote, bytes_left);
			disk_write (filesys_disk, fat_fs->bs.fat_start + i, bounce);
			bytes_wrote += bytes_left;
			free (bounce);
		}
	}
}

void
fat_create (void) {
	// Create FAT boot
	fat_boot_create ();
	fat_fs_init ();

	// Create FAT table
	fat_fs->fat = calloc (fat_fs->fat_length, sizeof (cluster_t));
	if (fat_fs->fat == NULL)
		PANIC ("FAT creation failed");

	// Set up ROOT_DIR_CLST
	fat_put (ROOT_DIR_CLUSTER, EOChain);

	// Fill up ROOT_DIR_CLUSTER region with 0
	uint8_t *buf = calloc (1, DISK_SECTOR_SIZE);
	if (buf == NULL)
		PANIC ("FAT create failed due to OOM");
	disk_write (filesys_disk, cluster_to_sector (ROOT_DIR_CLUSTER), buf);
	free (buf);
}

void
fat_boot_create (void) {
	unsigned int fat_sectors =
	    (disk_size (filesys_disk) - 1)
	    / (DISK_SECTOR_SIZE / sizeof (cluster_t) * SECTORS_PER_CLUSTER + 1) + 1;
	fat_fs->bs = (struct fat_boot){
	    .magic = FAT_MAGIC,
	    .sectors_per_cluster = SECTORS_PER_CLUSTER,
	    .total_sectors = disk_size (filesys_disk),
	    .fat_start = 1,
	    .fat_sectors = fat_sectors,
	    .root_dir_cluster = ROOT_DIR_CLUSTER,
	};
}

/* FAT 파일 시스템을 초기화합니다. 
 * 당신은 fat_fs의 fat_length와 data_start 필드를 초기화해야 합니다. 
 * fat_length는 파일시스템에 몇 개의 클러스터가 있는지에 대한 정보를 저장하고, 
 * data_start는 어떤 섹터에서 파일 저장을 시작할 수 있는지에 대한 정보를 저장합니다. 
 * 당신은 어쩌면 fat_fs->bs 에 저장된 값을 이용하고 싶어질 수도 있습니다. 
 * 또한, 이 함수에서 다른 유용한 데이터를 초기화하고 싶어질수도 있습니다. (하고싶으면 하라는 뜻) */
void
fat_fs_init (void) {
	/* TODO: Your code goes here. */
    // 파일시스템에 몇 개의 클러스터가 있는지에 대한 정보
    /* 클러스터는 Data area에서의 논리적 단위이므로, 
       [ 파일시스템에 존재하는 클러스터의 갯수 = ( filesys disk의 전체 섹터 수 - ( boot sector(1개) + fat가 차지하는 섹터 수 ) ) / 클러스터당 섹터 수 ] 이다. */
    fat_fs->fat_length = (fat_fs->bs.total_sectors - (1 + fat_fs->bs.fat_sectors)) / fat_fs->bs.sectors_per_cluster;

    // 어떤 섹터에서 파일 저장을 시작할 수 있는지에 대한 정보
    /* [ boot sector(1개) + fat가 차지하는 섹터 수 ] 이후 부터 데이터 영역으로 사용 가능한 섹터가 존재한다. */
    fat_fs->data_start = 1 + fat_fs->bs.fat_sectors;
    fat_fs->last_clst = fat_fs->fat_length - 1;

    lock_init(&fat_fs->write_lock);
}

/*----------------------------------------------------------------------------*/
/* FAT handling                                                               */
/*----------------------------------------------------------------------------*/

/* Add a cluster to the chain.
 * If CLST is 0, start a new chain.
 * Returns 0 if fails to allocate a new cluster. 
 * clst 인자(클러스터 인덱싱 넘버)로 특정된 클러스터 뒤에 다른 클러스터를 추가함으로써 체인을 연장합니다.
 * 만약 clst가 0이라면, 새로운 체인을 만듭니다.
 * 새롭게 할당된 클러스터의 넘버를 리턴합니다. */
cluster_t
fat_create_chain (cluster_t clst) {
	/* TODO: Your code goes here. */
    ASSERT(clst < fat_fs->fat_length);

    cluster_t new_clst = 0;
    fat_alloc_get_clst(&new_clst);

    ASSERT(new_clst != EOChain);

    if(clst != 0) {
        fat_put(clst, new_clst);
    }

    return new_clst;
}

/* Remove the chain of clusters starting from CLST.
 * If PCLST is 0, assume CLST as the start of the chain. 
 * clst로부터 시작하여, 체인으로부터 클러스터를 제거합니다. 
 * pclst는 체인에서의 clst 직전 클러스터여야 합니다. 
 * 이 말은, 이 함수가 실행되고 나면 pclst가 업데이트된 체인의 마지막 원소가 될 거라는 말입니다. 
 * 만일 clst가 체인의 첫 번째 원소라면, pclst의 값은 0이어야 할 겁니다. */
void
fat_remove_chain (cluster_t clst, cluster_t pclst) {
	/* TODO: Your code goes here. */
    cluster_t cur, next;

    if(pclst != 0) {
        ASSERT(fat_get(pclst) == clst);
    }

    cur = clst;
    do {
        next = fat_get(cur);
        fat_put(cur, FREE_ENTRY);   // remove
        cur = next;

        ASSERT(cur != FREE_ENTRY);
        ASSERT(0 < cur);
        ASSERT(cur <= fat_fs->last_clst);
    } while(cur != EOChain);
}

/* Update a value in the FAT table.
 * 클러스터 넘버 clst 가 가리키는 FAT 엔트리를 val로 업데이트합니다. 
 * FAT에 있는 각 엔트리는 체인에서의 다음 클러스터를 가리키고 있기 때문에 
 * (만약 존재한다면 그렇다는 거고, 다음 클러스터가 존재하지 않으면 EOChain (End Of Chain)입니다), 
 * 이 함수는 연결관계를 업데이트하기 위해 사용될 수 있습니다. */
void
fat_put (cluster_t clst, cluster_t val) {
	/* TODO: Your code goes here. */
    // memset(fat_fs->fat + clst, val, sizeof(cluster_t));
    *(fat_fs->fat + clst) = val;
}

/* Fetch a value in the FAT table. 
 * clst가 가리키는 클러스터 넘버를 리턴합니다. */
cluster_t
fat_get (cluster_t clst) {
	/* TODO: Your code goes here. */
    // uint8_t buffer;
    // memcpy(&buffer, fat_fs->fat + clst, sizeof(cluster_t));
    return (cluster_t)*(fat_fs->fat + clst);
}

/* Covert a cluster # to a sector number. 
 * 클러스터 넘버 clst를 상응하는 섹터 넘버로 변환하고, 그 섹터 넘버를 리턴합니다. */
disk_sector_t
cluster_to_sector (cluster_t clst) {
	/* TODO: Your code goes here. */
    return fat_fs->data_start + clst;
}

bool
fat_alloc_get_multiple(size_t cnt, disk_sector_t *sectorp) {
    ASSERT(0 < cnt && cnt <= fat_fs->last_clst);

    int clst_number = 2;
    cluster_t prev = EOChain;

    while(cnt > 0 || clst_number <= fat_fs->last_clst) {
        if(fat_get(clst_number) == FREE_ENTRY) {
            fat_put(clst_number, prev);
            prev = clst_number;
            cnt--;
        }
        clst_number++;
    }
    
    if(cnt != 0) {
        PANIC("filesys disk는 줄게 읎어....");
    }

    if(prev != EOChain) {
        *sectorp = prev;
    }
    return prev != EOChain;
}

bool
fat_alloc_get_clst(disk_sector_t *sectorp) {
    return fat_alloc_get_multiple(1, sectorp);
}
