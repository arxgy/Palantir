#include "stdio_impl.h"
#include <sys/uio.h>
#include<string.h>
#include <unistd.h>
#include "print.h"
size_t __stdio_read(FILE *f, unsigned char *buf, size_t len)
{
	struct iovec iov[2] = {
		{ .iov_base = buf, .iov_len = len - !!f->buf_size },
		{ .iov_base = f->buf, .iov_len = f->buf_size }
	};
	ssize_t cnt1 = 0;
	ssize_t cnt2 = 0;
	if(iov[0].iov_len){
		cnt1 = read(f->fd,iov[0].iov_base,iov[0].iov_len);
		if(cnt1 <= 0){
			f->flags |= cnt1? F_ERR: F_EOF;
			return 0;
		}
		cnt2 = read(f->fd,iov[1].iov_base,iov[1].iov_len);
		if(cnt2 <= 0){
			f->flags |= cnt2?F_ERR:F_EOF;
			return cnt1;
		}
		f->rpos = f->buf;
		f->rend = f->buf + cnt2;
		buf[len-1] = *f->rpos++;
		return len;
	}
	else{
		cnt2 = read(f->fd,iov[1].iov_base,iov[1].iov_len);
		if(cnt2 <= 0){
			f->flags |= cnt2?F_ERR:F_EOF;
			return 0;
		}
		f->rpos = f->buf;
		f->rend = f->buf + cnt2;
		buf[len-1] = *f->rpos++;
		return len;
	}
}
