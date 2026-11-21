//! The mailbox passes of a round: where they resume after a round the
//! budget cut short, and the scan that reads the relay's pages.

use super::*;

/// The relay sequence numbers after which the two mailbox passes of the next
/// round start. Both are zero (the beginning) unless the last round was cut
/// short by its budget. They are positions chosen by the untrusted relay and
/// are used only as a starting point: any error, and every round that runs
/// to the end, puts them back to zero, so everything skipped is read again.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Resume {
    pub(super) handshakes: u64,
    pub(super) messages: u64,
}

/// The part of the mailbox one pass reads: sequence numbers after `from`, up
/// to and including `until`.
#[derive(Debug, Clone, Copy)]
pub(super) struct Span {
    pub(super) from: u64,
    pub(super) until: u64,
}

/// How one mailbox pass ended.
#[derive(Debug, Clone, Copy)]
pub(super) struct ScanEnd {
    /// The last sequence number the pass reached (where it started, if it
    /// saw nothing).
    pub(super) reached: u64,
    /// Whether it ran to the end of its part of the mailbox. False only when
    /// the round's budget stopped it.
    pub(super) complete: bool,
}

impl NetworkMessenger {
    /// One pass over this device's mailbox: pages through it in ascending
    /// relay order with FETCH_AFTER, processes the envelopes `pass` selects
    /// among those numbered up to `until`, and deletes from the relay exactly
    /// those whose fate is [`Fate::Delete`]. Envelopes kept, and envelopes the
    /// pass does not select, stay on the relay, and paging moves past them:
    /// a retained prefix cannot hide what follows it.
    ///
    /// At most [`MAX_SCAN_PAGES`] pages and [`MAX_SCAN_ENVELOPES`] envelopes;
    /// the pass ends early on a page shorter than [`MIN_PAGE`], which the relay
    /// only returns when nothing follows, and on reaching `until`. The pass
    /// starts after `from`: zero, the beginning, except in the round after
    /// one its budget cut short (see [`Resume`]). Sequence numbers are
    /// transport positions chosen by the untrusted relay, never evidence of
    /// anything. A relay that does not return strictly increasing numbers
    /// after the cursor ends the round with an error.
    ///
    /// The first page is always read; before each later one the round's
    /// budget is checked, and a pass it stops returns `complete: false`.
    pub(super) fn scan(
        &self,
        conn: &mut Connection,
        our: [u8; 32],
        pass: Pass,
        span: Span,
        budget: &Budget,
        report: &mut SyncReport,
    ) -> Result<ScanEnd, CoreError> {
        let Span { from, until } = span;
        let mut after = from;
        let mut complete = true;
        let mut seen = 0usize;
        let mut delete = Vec::new();
        'pages: for page in 0..MAX_SCAN_PAGES {
            // Out of time: stop after the page in hand and delete what was
            // processed. The first page of a pass is always read, so each
            // round moves both passes on by at least a page; the next round
            // starts after it.
            if page > 0 && !budget.left() {
                complete = false;
                break;
            }
            let items = conn.fetch_after(our, after, MAX_FETCH).map_err(network)?;
            if items.len() > MAX_FETCH as usize {
                return Err(CoreError::Network {
                    msg: "relay returned more envelopes than asked for".into(),
                });
            }
            if items.is_empty() {
                break;
            }
            #[cfg(test)]
            scan_hook::run(pass, page);
            let last = items.len() < MIN_PAGE;
            for (seq, bytes) in items {
                if seq <= after {
                    return Err(CoreError::Network {
                        msg: "relay returned envelopes out of order".into(),
                    });
                }
                if seq > until {
                    break 'pages;
                }
                after = seq;
                seen += 1;
                if pass == Pass::Handshakes {
                    report.fetched += 1;
                }
                let env = Envelope::decode(&bytes);
                let handshake = matches!(env, Some(Envelope::Handshake { .. }));
                if handshake == (pass == Pass::Handshakes) {
                    let fate = match env {
                        None => {
                            report.dropped += 1;
                            Fate::Delete
                        }
                        Some(env) => self.process(env, report)?,
                    };
                    match fate {
                        Fate::Delete => delete.push(seq),
                        Fate::Keep => report.deferred += 1,
                    }
                }
                if seen == MAX_SCAN_ENVELOPES || seq == until {
                    break 'pages;
                }
            }
            if pass == Pass::Messages {
                crash_point("after_page");
            }
            if last {
                break;
            }
        }
        if !delete.is_empty() {
            conn.delete(our, delete).map_err(network)?;
            if pass == Pass::Messages {
                crash_point("after_delete");
            }
        }
        Ok(ScanEnd {
            reached: after,
            complete,
        })
    }
}
