/**
 * What a failure means, and who has to act on it. R7.6.
 *
 * DR-010: an exit code names what the caller has to do about a failure, not
 * what the code was doing when it noticed. That is a designed contract and a
 * client that renders every failure as a stack trace throws it away — so the
 * number is what decides the sentence here, and nothing else is parsed. The
 * daemon's own message is carried through as the reason, because
 * `docs/conventions.md` §10 puts the rendered sentence in the frontend and the
 * daemon has already rendered one that names the archive, the handle, the
 * respelt path or the entry.
 *
 * On the wire a negative code is JSON-RPC's own and a positive one is the exit
 * code the command line would use. DR-008.
 */

/** Exit codes, as `crates/rpf/src/exit.rs` declares them. */
export const EXIT = {
    ok: 0,
    internal: 1,
    usage: 2,
    notFound: 3,
    corrupt: 4,
    needsKey: 5,
    refused: 6,
    io: 7,
    cancelled: 8,
    unsupported: 9,
} as const;

/** JSON-RPC's own codes, for a request that did not follow the protocol. */
export const PROTOCOL = {
    invalidRequest: -32600,
    methodNotFound: -32601,
    invalidParams: -32602,
    parseError: -32700,
} as const;

/** Which class of failure this is, and therefore who has to act. */
export type Kind =
    | 'pending'
    | 'protocol'
    | 'internal'
    | 'usage'
    | 'not-found'
    | 'corrupt'
    | 'needs-key'
    | 'refused'
    | 'io'
    | 'cancelled'
    | 'unsupported'
    | 'transport'
    | 'unknown';

/** A failure the daemon answered a request with. */
export class DaemonError extends Error {
    /** Negative is JSON-RPC's own; positive is the exit code. */
    readonly code: number;
    /** Which method was rejected. */
    readonly method: string;
    /** What the daemon said, unaltered. */
    readonly reason: string;

    constructor(method: string, code: number, reason: string) {
        super(`rpf ${method}: ${reason}`);
        this.name = 'DaemonError';
        this.code = code;
        this.method = method;
        this.reason = reason;
    }
}

/**
 * What a caller has to do about a change this client declined to offer.
 *
 * A category rather than a rendered sentence, for `docs/conventions.md` §10's
 * reason: an editor has its own small vocabulary for filesystem failures and
 * picks from it by this, while the message is what a person reads.
 */
export type RefusalKind = 'exists' | 'not-found' | 'is-a-directory' | 'refused';

/**
 * A change the client's own view of the archive refuses before the daemon is
 * asked for it.
 *
 * Its own type because the daemon cannot answer it: every buffered change is
 * resolved against the archive **on disk**, so a path a buffered change created
 * is not there to be found and a path a buffered removal freed is still
 * occupied. The client is the only side that holds both. DR-030.
 */
export class Refused extends Error {
    /** Which answer an editor's filesystem vocabulary has for this. */
    readonly kind: RefusalKind;
    /** The path inside the archive the refusal is about. */
    readonly path: string;

    constructor(kind: RefusalKind, path: string, message: string) {
        super(message);
        this.name = 'Refused';
        this.kind = kind;
        this.path = path;
    }
}

/**
 * A failure of the connection rather than of a request: the daemon could not be
 * started, died, or stopped answering.
 *
 * Its own type because nobody's input is in question, which is exactly what
 * exit 7 means, and a client that reported it as a refusal would be telling the
 * user to change a request that was never read.
 */
export class TransportError extends Error {
    /** Whatever the process left on standard error, when there was any. */
    readonly diagnostics: string;

    constructor(message: string, diagnostics = '') {
        super(message);
        this.name = 'TransportError';
        this.diagnostics = diagnostics;
    }
}

/** What the user is told, and what they are told to do about it. */
export interface Advice {
    kind: Kind;
    /** The code that decided it. `null` when there was no wire failure. */
    code: number | null;
    /** One line naming what went wrong, in the user's terms. */
    headline: string;
    /** What the user has to do. Never empty. */
    action: string;
    /** The daemon's own sentence, which names the path, handle or entry. */
    reason: string;
}

/** Which kind a wire code belongs to. */
export function kindOf(code: number): Kind {
    if (code < 0) {
        return 'protocol';
    }
    switch (code) {
        case EXIT.internal:
            return 'internal';
        case EXIT.usage:
            return 'usage';
        case EXIT.notFound:
            return 'not-found';
        case EXIT.corrupt:
            return 'corrupt';
        case EXIT.needsKey:
            return 'needs-key';
        case EXIT.refused:
            return 'refused';
        case EXIT.io:
            return 'io';
        case EXIT.cancelled:
            return 'cancelled';
        case EXIT.unsupported:
            return 'unsupported';
        default:
            return 'unknown';
    }
}

/** The headline and the instruction each kind carries. */
const COUNSEL: Record<Kind, { headline: string; action: string }> = {
    pending: {
        headline: 'This change cannot be buffered beside the ones already waiting to be saved.',
        action: 'Save the archive, or discard the buffered changes, and then make this one. The archive on disk is untouched either way.',
    },
    protocol: {
        headline: 'The extension sent a request the daemon could not accept.',
        action: 'This is a fault in the extension rather than in the archive. Report it with the daemon log; nothing you change about the archive will help.',
    },
    internal: {
        headline: 'rpf failed in a way it has no classification for.',
        action: 'Report it with the daemon log. The archive is not implicated.',
    },
    usage: {
        headline: 'rpf was called with arguments it does not accept.',
        action: 'This is a fault in the extension. Report it with the daemon log.',
    },
    'not-found': {
        headline: 'There is no such file in the archive.',
        action: 'Check the path against the listing. Inside an archive the separator is / on every platform, and a backslash is an ordinary character in an entry name rather than a separator.',
    },
    corrupt: {
        headline: 'The archive does not hold together: its bytes contradict what it says about them.',
        action: 'Nothing you supply will make it open. Run "RPF: Verify Archive" to see which entries fail, and get an undamaged copy of the archive.',
    },
    'needs-key': {
        headline: 'This archive is encrypted, and no key material is available.',
        action: 'rpf never bundles keys — it reads them from your own game install — and this build cannot decrypt archive contents at all. An encrypted archive cannot be opened here; work on an unencrypted one.',
    },
    refused: {
        headline: 'rpf declined to carry out the request.',
        action: 'The request or its input has to change; the reason below says which part. Nothing is wrong with the archive.',
    },
    io: {
        headline: 'A read or a write failed.',
        action: 'Nobody\'s input is in question — the source or the sink failed. Check that the file is still there and still readable, then try again.',
    },
    cancelled: {
        headline: 'The operation was stopped part-way, as asked.',
        action: 'Nothing was left half-written: a cancelled rebuild leaves the original archive untouched. Start it again when you are ready.',
    },
    unsupported: {
        headline: 'The archive is intact, and this build cannot read its container version.',
        action: 'Nobody holding the archive can act on this — the missing part is here. It needs a build of rpf with a codec for that version.',
    },
    transport: {
        headline: 'The rpf daemon is not answering.',
        action: 'Check the binary named in the rpf.binaryPath setting, then reload the window to start a new daemon.',
    },
    unknown: {
        headline: 'rpf reported a failure this extension does not recognise.',
        action: 'The extension is older than the daemon it is talking to. Update the extension, or check the daemon log.',
    },
};

/**
 * What to tell the user about a failure, and what to tell them to do.
 *
 * Everything that is not a {@link DaemonError} or a {@link TransportError} is
 * an internal fault of this extension, and says so rather than being dressed up
 * as an archive problem.
 */
export function advise(failure: unknown): Advice {
    if (failure instanceof Refused) {
        const counsel = COUNSEL.pending;
        return {
            kind: 'pending',
            code: null,
            headline: counsel.headline,
            action: counsel.action,
            reason: failure.message,
        };
    }
    if (failure instanceof DaemonError) {
        const kind = kindOf(failure.code);
        const counsel = COUNSEL[kind];
        return {
            kind,
            code: failure.code,
            headline: counsel.headline,
            action: counsel.action,
            reason: failure.reason,
        };
    }
    if (failure instanceof TransportError) {
        const counsel = COUNSEL.transport;
        return {
            kind: 'transport',
            code: null,
            headline: counsel.headline,
            action: counsel.action,
            reason: failure.diagnostics ? `${failure.message}\n${failure.diagnostics}` : failure.message,
        };
    }
    const counsel = COUNSEL.internal;
    return {
        kind: 'internal',
        code: null,
        headline: counsel.headline,
        action: counsel.action,
        reason: failure instanceof Error ? failure.message : String(failure),
    };
}

/**
 * Which of an editor filesystem's own failures a failure is.
 *
 * Here rather than in the editor adapter so it can be checked without an
 * editor: this is the whole of R7.6 for the filesystem surface, and an adapter
 * that decided it would be the one place nothing tests. A {@link Refused} says
 * which word it means, because the client's own view is what decided it; a
 * {@link DaemonError} reaches one through DR-010's classification, and nothing
 * about its sentence is parsed.
 */
export type FileSystemWord =
    | 'exists'
    | 'not-found'
    | 'is-a-directory'
    | 'no-permissions'
    | 'unavailable'
    | 'other';

/** Which of an editor's filesystem failures this one is. */
export function fileSystemWordFor(failure: unknown): FileSystemWord {
    if (failure instanceof Refused) {
        return failure.kind === 'refused' ? 'no-permissions' : failure.kind;
    }
    if (failure instanceof TransportError) {
        return 'unavailable';
    }
    if (failure instanceof DaemonError) {
        switch (failure.code) {
            case EXIT.notFound:
                return 'not-found';
            case EXIT.refused:
                return 'no-permissions';
            case EXIT.io:
                return 'unavailable';
            default:
                return 'other';
        }
    }
    return 'other';
}

/** The advice as one block of text, for a notification or a log line. */
export function render(advice: Advice): string {
    return `${advice.headline}\n${advice.reason}\n${advice.action}`;
}
