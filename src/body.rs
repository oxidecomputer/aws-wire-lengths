use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::StreamExt;
use http_body::{Body, Frame};
use tokio::io::Stdin;
use tokio_util::io::ReaderStream;

pub struct StreamBody {
    inner: ReaderStream<Stdin>,
}

impl StreamBody {
    pub fn new(inner: ReaderStream<Stdin>) -> StreamBody {
        StreamBody { inner }
    }
}

impl Body for StreamBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.inner.poll_next_unpin(cx) {
            Poll::Ready(res) => match res {
                Some(res) => Poll::Ready(Some(res.map(|buf| Frame::data(buf)))),
                None => Poll::Ready(None),
            },
            Poll::Pending => Poll::Pending,
        }
    }
}
