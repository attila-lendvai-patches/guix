;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012, 2013 Ludovic Courtès <ludo@gnu.org>
;;;
;;; This file is part of GNU Guix.
;;;
;;; GNU Guix is free software; you can redistribute it and/or modify it
;;; under the terms of the GNU General Public License as published by
;;; the Free Software Foundation; either version 3 of the License, or (at
;;; your option) any later version.
;;;
;;; GNU Guix is distributed in the hope that it will be useful, but
;;; WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;; GNU General Public License for more details.
;;;
;;; You should have received a copy of the GNU General Public License
;;; along with GNU Guix.  If not, see <http://www.gnu.org/licenses/>.

(define-module (guix store)
  #:use-module (guix utils)
  #:use-module (guix config)
  #:use-module (rnrs bytevectors)
  #:use-module (rnrs io ports)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-9)
  #:use-module (srfi srfi-26)
  #:use-module (srfi srfi-34)
  #:use-module (srfi srfi-35)
  #:use-module (srfi srfi-39)
  #:use-module (ice-9 match)
  #:use-module (ice-9 rdelim)
  #:use-module (ice-9 ftw)
  #:use-module (ice-9 regex)
  #:export (nix-server?
            nix-server-major-version
            nix-server-minor-version
            nix-server-socket

            &nix-error nix-error?
            &nix-protocol-error nix-protocol-error?
            nix-protocol-error-message
            nix-protocol-error-status

            hash-algo

            open-connection
            close-connection
            set-build-options
            valid-path?
            query-path-hash
            add-text-to-store
            add-to-store
            build-derivations
            add-temp-root
            add-indirect-root

            substitutable?
            substitutable-path
            substitutable-deriver
            substitutable-references
            substitutable-download-size
            substitutable-nar-size
            has-substitutes?
            substitutable-paths
            substitutable-path-info

            live-paths
            dead-paths
            collect-garbage
            delete-paths

            current-build-output-port

            %store-prefix
            store-path?
            derivation-path?
            store-path-package-name))

(define %protocol-version #x10c)

(define %worker-magic-1 #x6e697863)
(define %worker-magic-2 #x6478696f)

(define (protocol-major magic)
  (logand magic #xff00))
(define (protocol-minor magic)
  (logand magic #x00ff))

(define-syntax define-enumerate-type
  (syntax-rules ()
    ((_ name->int (name id) ...)
     (define-syntax name->int
       (syntax-rules (name ...)
         ((_ name) id) ...)))))

(define-enumerate-type operation-id
  ;; operation numbers from worker-protocol.hh
  (quit 0)
  (valid-path? 1)
  (has-substitutes? 3)
  (query-path-hash 4)
  (query-references 5)
  (query-referrers 6)
  (add-to-store 7)
  (add-text-to-store 8)
  (build-derivations 9)
  (ensure-path 10)
  (add-temp-root 11)
  (add-indirect-root 12)
  (sync-with-gc 13)
  (find-roots 14)
  (export-path 16)
  (query-deriver 18)
  (set-options 19)
  (collect-garbage 20)
  ;;(query-substitutable-path-info 21)  ; obsolete as of #x10c
  (query-derivation-outputs 22)
  (query-all-valid-paths 23)
  (query-failed-paths 24)
  (clear-failed-paths 25)
  (query-path-info 26)
  (import-paths 27)
  (query-derivation-output-names 28)
  (query-path-from-hash-part 29)
  (query-substitutable-path-infos 30)
  (query-valid-paths 31)
  (query-substitutable-paths 32))

(define-enumerate-type hash-algo
  ;; hash.hh
  (md5 1)
  (sha1 2)
  (sha256 3))

(define-enumerate-type gc-action
  ;; store-api.hh
  (return-live 0)
  (return-dead 1)
  (delete-dead 2)
  (delete-specific 3))

(define %default-socket-path
  (string-append (or (getenv "NIX_STATE_DIR") %state-directory)
                 "/daemon-socket/socket"))


;; serialize.cc

(define (write-int n p)
  (let ((b (make-bytevector 8 0)))
    (bytevector-u32-set! b 0 n (endianness little))
    (put-bytevector p b)))

(define (read-int p)
  (let ((b (get-bytevector-n p 8)))
    (bytevector-u32-ref b 0 (endianness little))))

(define (write-long-long n p)
  (let ((b (make-bytevector 8 0)))
    (bytevector-u64-set! b 0 n (endianness little))
    (put-bytevector p b)))

(define (read-long-long p)
  (let ((b (get-bytevector-n p 8)))
    (bytevector-u64-ref b 0 (endianness little))))

(define write-padding
  (let ((zero (make-bytevector 8 0)))
    (lambda (n p)
      (let ((m (modulo n 8)))
        (or (zero? m)
            (put-bytevector p zero 0 (- 8 m)))))))

(define (write-string s p)
  (let* ((s (string->utf8 s))
         (l (bytevector-length s))
         (m (modulo l 8))
         (b (make-bytevector (+ 8 l (if (zero? m) 0 (- 8 m))))))
    (bytevector-u32-set! b 0 l (endianness little))
    (bytevector-copy! s 0 b 8 l)
    (put-bytevector p b)))

(define (read-string p)
  (let* ((len (read-int p))
         (m   (modulo len 8))
         (bv  (get-bytevector-n p len))
         (str (utf8->string bv)))
    (or (zero? m)
        (get-bytevector-n p (- 8 m)))
    str))

(define (read-latin1-string p)
  (let* ((len (read-int p))
         (m   (modulo len 8))
         (str (get-string-n p len)))
    (or (zero? m)
        (get-bytevector-n p (- 8 m)))
    str))

(define (write-string-list l p)
  (write-int (length l) p)
  (for-each (cut write-string <> p) l))

(define (read-string-list p)
  (let ((len (read-int p)))
    (unfold (cut >= <> len)
            (lambda (i)
              (read-string p))
            1+
            0)))

(define (write-store-path f p)
  (write-string f p))                             ; TODO: assert path

(define (read-store-path p)
  (read-string p))                                ; TODO: assert path

(define write-store-path-list write-string-list)
(define read-store-path-list read-string-list)

(define (write-contents file p)
  "Write the contents of FILE to output port P."
  (define (dump in size)
    (define buf-size 65536)
    (define buf (make-bytevector buf-size))

    (let loop ((left size))
      (if (<= left 0)
          0
          (let ((read (get-bytevector-n! in buf 0 buf-size)))
            (if (eof-object? read)
                left
                (begin
                  (put-bytevector p buf 0 read)
                  (loop (- left read))))))))

  (let ((size (stat:size (lstat file))))
    (write-string "contents" p)
    (write-long-long size p)
    (call-with-input-file file
      (lambda (p)
        (dump p size)))
    (write-padding size p)))

(define (write-file f p)
  (define %archive-version-1 "nix-archive-1")

  (write-string %archive-version-1 p)

  (let dump ((f f))
    (let ((s (lstat f)))
      (write-string "(" p)
      (case (stat:type s)
        ((regular)
         (write-string "type" p)
         (write-string "regular" p)
         (if (not (zero? (logand (stat:mode s) #o100)))
             (begin
               (write-string "executable" p)
               (write-string "" p)))
         (write-contents f p))
        ((directory)
         (write-string "type" p)
         (write-string "directory" p)
         (let ((entries (remove (cut member <> '("." ".."))
                                (scandir f))))
           (for-each (lambda (e)
                       (let ((f (string-append f "/" e)))
                         (write-string "entry" p)
                         (write-string "(" p)
                         (write-string "name" p)
                         (write-string e p)
                         (write-string "node" p)
                         (dump f)
                         (write-string ")" p)))
                     entries)))
        (else
         (error "ENOSYS")))
      (write-string ")" p))))

;; Information about a substitutable store path.
(define-record-type <substitutable>
  (substitutable path deriver refs dl-size nar-size)
  substitutable?
  (path      substitutable-path)
  (deriver   substitutable-deriver)
  (refs      substitutable-references)
  (dl-size   substitutable-download-size)
  (nar-size  substitutable-nar-size))

(define (read-substitutable-path-list p)
  (let loop ((len    (read-int p))
             (result '()))
    (if (zero? len)
        (reverse result)
        (let ((path     (read-store-path p))
              (deriver  (read-store-path p))
              (refs     (read-store-path-list p))
              (dl-size  (read-long-long p))
              (nar-size (read-long-long p)))
          (loop (- len 1)
                (cons (substitutable path deriver refs dl-size nar-size)
                      result))))))

(define-syntax write-arg
  (syntax-rules (integer boolean file string string-list
                 store-path store-path-list base16)
    ((_ integer arg p)
     (write-int arg p))
    ((_ boolean arg p)
     (write-int (if arg 1 0) p))
    ((_ file arg p)
     (write-file arg p))
    ((_ string arg p)
     (write-string arg p))
    ((_ string-list arg p)
     (write-string-list arg p))
    ((_ store-path arg p)
     (write-store-path arg p))
    ((_ store-path-list arg p)
     (write-store-path-list arg p))
    ((_ base16 arg p)
     (write-string (bytevector->base16-string arg) p))))

(define-syntax read-arg
  (syntax-rules (integer boolean string store-path store-path-list
                 substitutable-path-list base16)
    ((_ integer p)
     (read-int p))
    ((_ boolean p)
     (not (zero? (read-int p))))
    ((_ string p)
     (read-string p))
    ((_ store-path p)
     (read-store-path p))
    ((_ store-path-list p)
     (read-store-path-list p))
    ((_ substitutable-path-list p)
     (read-substitutable-path-list p))
    ((_ base16 p)
     (base16-string->bytevector (read-string p)))))


;; remote-store.cc

(define-record-type <nix-server>
  (%make-nix-server socket major minor
                    ats-cache atts-cache)
  nix-server?
  (socket nix-server-socket)
  (major  nix-server-major-version)
  (minor  nix-server-minor-version)

  ;; Caches.  We keep them per-connection, because store paths build
  ;; during the session are temporary GC roots kept for the duration of
  ;; the session.
  (ats-cache  nix-server-add-to-store-cache)
  (atts-cache nix-server-add-text-to-store-cache))

(define-condition-type &nix-error &error
  nix-error?)

(define-condition-type &nix-protocol-error &nix-error
  nix-protocol-error?
  (message nix-protocol-error-message)
  (status  nix-protocol-error-status))

(define* (open-connection #:optional (file %default-socket-path)
                          #:key (reserve-space? #t))
  "Connect to the daemon over the Unix-domain socket at FILE.  When
RESERVE-SPACE? is true, instruct it to reserve a little bit of extra
space on the file system so that the garbage collector can still
operate, should the disk become full.  Return a server object."
  (let ((s (with-fluids ((%default-port-encoding #f))
             ;; This trick allows use of the `scm_c_read' optimization.
             (socket PF_UNIX SOCK_STREAM 0)))
        (a (make-socket-address PF_UNIX file)))

    ;; Enlarge the receive buffer.
    (setsockopt s SOL_SOCKET SO_RCVBUF (* 12 1024))

    (connect s a)
    (write-int %worker-magic-1 s)
    (let ((r (read-int s)))
      (and (eqv? r %worker-magic-2)
           (let ((v (read-int s)))
             (and (eqv? (protocol-major %protocol-version)
                        (protocol-major v))
                  (begin
                    (write-int %protocol-version s)
                    (if (>= (protocol-minor v) 11)
                        (write-int (if reserve-space? 1 0) s))
                    (let ((s (%make-nix-server s
                                               (protocol-major v)
                                               (protocol-minor v)
                                               (make-hash-table 100)
                                               (make-hash-table 100))))
                      (let loop ((done? (process-stderr s)))
                        (or done? (process-stderr s)))
                      s))))))))

(define (close-connection server)
  "Close the connection to SERVER."
  (close (nix-server-socket server)))

(define current-build-output-port
  ;; The port where build output is sent.
  (make-parameter (current-error-port)))

(define (process-stderr server)
  "Read standard output and standard error from SERVER, writing it to
CURRENT-BUILD-OUTPUT-PORT.  Return #t when SERVER is done sending data, and
#f otherwise; in the latter case, the caller should call `process-stderr'
again until #t is returned or an error is raised.

Since the build process's output cannot be assumed to be UTF-8, we
conservatively consider it to be Latin-1, thereby avoiding possible
encoding conversion errors."
  (define p
    (nix-server-socket server))

  ;; magic cookies from worker-protocol.hh
  (define %stderr-next  #x6f6c6d67)
  (define %stderr-read  #x64617461)               ; data needed from source
  (define %stderr-write #x64617416)               ; data for sink
  (define %stderr-last  #x616c7473)
  (define %stderr-error #x63787470)

  (let ((k (read-int p)))
    (cond ((= k %stderr-write)
           (read-latin1-string p)
           #f)
          ((= k %stderr-read)
           (let ((len (read-int p)))
             (read-latin1-string p)               ; FIXME: what to do?
             #f))
          ((= k %stderr-next)
           (let ((s (read-latin1-string p)))
             (display s (current-build-output-port))
             #f))
          ((= k %stderr-error)
           (let ((error  (read-latin1-string p))
                 (status (if (>= (nix-server-minor-version server) 8)
                             (read-int p)
                             1)))
             (raise (condition (&nix-protocol-error
                                (message error)
                                (status  status))))))
          ((= k %stderr-last)
           ;; The daemon is done (see `stopWork' in `nix-worker.cc'.)
           #t)
          (else
           (raise (condition (&nix-protocol-error
                              (message "invalid error code")
                              (status   k))))))))

(define* (set-build-options server
                            #:key keep-failed? keep-going? try-fallback?
                            (verbosity 0)
                            (max-build-jobs (current-processor-count))
                            (max-silent-time 3600)
                            (use-build-hook? #t)
                            (build-verbosity 0)
                            (log-type 0)
                            (print-build-trace #t)
                            (build-cores 1)
                            (use-substitutes? #t)
                            (binary-caches '())) ; client "untrusted" cache URLs
  ;; Must be called after `open-connection'.

  (define socket
    (nix-server-socket server))

  (let-syntax ((send (syntax-rules ()
                       ((_ (type option) ...)
                        (begin
                          (write-arg type option socket)
                          ...)))))
    (write-int (operation-id set-options) socket)
    (send (boolean keep-failed?) (boolean keep-going?)
          (boolean try-fallback?) (integer verbosity)
          (integer max-build-jobs) (integer max-silent-time))
    (if (>= (nix-server-minor-version server) 2)
        (send (boolean use-build-hook?)))
    (if (>= (nix-server-minor-version server) 4)
        (send (integer build-verbosity) (integer log-type)
              (boolean print-build-trace)))
    (if (>= (nix-server-minor-version server) 6)
        (send (integer build-cores)))
    (if (>= (nix-server-minor-version server) 10)
        (send (boolean use-substitutes?)))
    (if (>= (nix-server-minor-version server) 12)
        (send (string-list (fold-right (lambda (pair result)
                                         (match pair
                                           ((h . t)
                                            (cons* h t result))))
                                       '()
                                       binary-caches))))
    (let loop ((done? (process-stderr server)))
      (or done? (process-stderr server)))))

(define-syntax operation
  (syntax-rules ()
    "Define a client-side RPC stub for the given operation."
    ((_ (name (type arg) ...) docstring return ...)
     (lambda (server arg ...)
       docstring
       (let ((s (nix-server-socket server)))
         (write-int (operation-id name) s)
         (write-arg type arg s)
         ...
         ;; Loop until the server is done sending error output.
         (let loop ((done? (process-stderr server)))
           (or done? (loop (process-stderr server))))
         (values (read-arg return s) ...))))))

(define-syntax-rule (define-operation (name args ...)
                      docstring return ...)
  (define name
    (operation (name args ...) docstring return ...)))

(define-operation (valid-path? (string path))
  "Return #t when PATH is a valid store path."
  boolean)

(define-operation (query-path-hash (store-path path))
  "Return the SHA256 hash of PATH as a bytevector."
  base16)

(define add-text-to-store
  ;; A memoizing version of `add-to-store', to avoid repeated RPCs with
  ;; the very same arguments during a given session.
  (let ((add-text-to-store
         (operation (add-text-to-store (string name) (string text)
                                       (string-list references))
                    #f
                    store-path)))
    (lambda (server name text references)
      "Add TEXT under file NAME in the store, and return its store path.
REFERENCES is the list of store paths referred to by the resulting store
path."
      (let ((args  `(,text ,name ,references))
            (cache (nix-server-add-text-to-store-cache server)))
        (or (hash-ref cache args)
            (let ((path (add-text-to-store server name text references)))
              (hash-set! cache args path)
              path))))))

(define add-to-store
  ;; A memoizing version of `add-to-store'.  This is important because
  ;; `add-to-store' leads to huge data transfers to the server, and
  ;; because it's often called many times with the very same argument.
  (let ((add-to-store (operation (add-to-store (string basename)
                                               (boolean fixed?) ; obsolete, must be #t
                                               (boolean recursive?)
                                               (string hash-algo)
                                               (file file-name))
                                 #f
                                 store-path)))
    (lambda (server basename recursive? hash-algo file-name)
      "Add the contents of FILE-NAME under BASENAME to the store.  When
RECURSIVE? is true and FILE-NAME designates a directory, the contents of
FILE-NAME are added recursively; if FILE-NAME designates a flat file and
RECURSIVE? is true, its contents are added, and its permission bits are
kept.  HASH-ALGO must be a string such as \"sha256\"."
      (let* ((st    (stat file-name #f))
             (args  `(,st ,basename ,recursive? ,hash-algo))
             (cache (nix-server-add-to-store-cache server)))
        (or (and st (hash-ref cache args))
            (let ((path (add-to-store server basename #t recursive?
                                      hash-algo file-name)))
              (hash-set! cache args path)
              path))))))

(define-operation (build-derivations (string-list derivations))
  "Build DERIVATIONS, and return when the worker is done building them.
Return #t on success."
  boolean)

(define-operation (add-temp-root (store-path path))
  "Make PATH a temporary root for the duration of the current session.
Return #t."
  boolean)

(define-operation (add-indirect-root (string file-name))
  "Make FILE-NAME an indirect root for the garbage collector; FILE-NAME
can be anywhere on the file system, but it must be an absolute file
name--it is the caller's responsibility to ensure that it is an absolute
file name.  Return #t on success."
  boolean)

(define-operation (has-substitutes? (store-path path))
  "Return #t if binary substitutes are available for PATH, and #f otherwise."
  boolean)

(define substitutable-paths
  (operation (query-substitutable-paths (store-path-list paths))
             "Return the subset of PATHS that is substitutable."
             store-path-list))

(define substitutable-path-info
  (operation (query-substitutable-paths (store-path-list paths))
             "Return information about the subset of PATHS that is
substitutable.  For each substitutable path, a `substitutable?' object is
returned."
             substitutable-path-list))

(define (run-gc server action to-delete min-freed)
  "Perform the garbage-collector operation ACTION, one of the
`gc-action' values.  When ACTION is `delete-specific', the TO-DELETE is
the list of store paths to delete.  IGNORE-LIVENESS? should always be
#f.  MIN-FREED is the minimum amount of disk space to be freed, in
bytes, before the GC can stop.  Return the list of store paths delete,
and the number of bytes freed."
  (let ((s (nix-server-socket server)))
    (write-int (operation-id collect-garbage) s)
    (write-int action s)
    (write-store-path-list to-delete s)
    (write-arg boolean #f s)                      ; ignore-liveness?
    (write-long-long min-freed s)
    (write-int 0 s)                               ; obsolete
    (when (>= (nix-server-minor-version server) 5)
      ;; Obsolete `use-atime' and `max-atime' parameters.
      (write-int 0 s)
      (write-int 0 s))

    ;; Loop until the server is done sending error output.
    (let loop ((done? (process-stderr server)))
      (or done? (loop (process-stderr server))))

    (let ((paths    (read-store-path-list s))
          (freed    (read-long-long s))
          (obsolete (read-long-long s)))
     (values paths freed))))

(define-syntax-rule (%long-long-max)
  ;; Maximum unsigned 64-bit integer.
  (- (expt 2 64) 1))

(define (live-paths server)
  "Return the list of live store paths---i.e., store paths still
referenced, and thus not subject to being garbage-collected."
  (run-gc server (gc-action return-live) '() (%long-long-max)))

(define (dead-paths server)
  "Return the list of dead store paths---i.e., store paths no longer
referenced, and thus subject to being garbage-collected."
  (run-gc server (gc-action return-dead) '() (%long-long-max)))

(define* (collect-garbage server #:optional (min-freed (%long-long-max)))
  "Collect garbage from the store at SERVER.  If MIN-FREED is non-zero,
then collect at least MIN-FREED bytes.  Return the paths that were
collected, and the number of bytes freed."
  (run-gc server (gc-action delete-dead) '() min-freed))

(define* (delete-paths server paths #:optional (min-freed (%long-long-max)))
  "Delete PATHS from the store at SERVER, if they are no longer
referenced.  If MIN-FREED is non-zero, then stop after at least
MIN-FREED bytes have been collected.  Return the paths that were
collected, and the number of bytes freed."
  (run-gc server (gc-action delete-specific) paths min-freed))


;;;
;;; Store paths.
;;;

(define %store-prefix
  ;; Absolute path to the Nix store.
  (make-parameter (or (and=> (getenv "NIX_STORE_DIR") canonicalize-path)
                      %store-directory)))

(define (store-path? path)
  "Return #t if PATH is a store path."
  ;; This is a lightweight check, compared to using a regexp, but this has to
  ;; be fast as it's called often in `derivation', for instance.
  ;; `isStorePath' in Nix does something similar.
  (string-prefix? (%store-prefix) path))

(define (derivation-path? path)
  "Return #t if PATH is a derivation path."
  (and (store-path? path) (string-suffix? ".drv" path)))

(define (store-path-package-name path)
  "Return the package name part of PATH, a file name in the store."
  (define store-path-rx
    (make-regexp (string-append "^.*" (regexp-quote (%store-prefix))
                                "/[^-]+-(.+)$")))

  (and=> (regexp-exec store-path-rx path)
         (cut match:substring <> 1)))
