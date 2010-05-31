#include <stdio.h>
#include <fcntl.h>


main()
{
	int fp;
	unsigned char c;

	if (!(fp = open("/etc/resolv.conf", O_RDONLY))) {
		perror("open");
		exit(1);
	}
	while (read(fp, &c, 1)) {
		write(1, &c, 1);
	}
	close(fp);

}
