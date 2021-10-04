;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2020 Katherine Cox-Buday <cox.katherine.e@gmail.com>
;;; Copyright © 2020 Helio Machado <0x2b3bfa0+guix@googlemail.com>
;;; Copyright © 2021 François Joulaud <francois.joulaud@radiofrance.com>
;;; Copyright © 2021 Maxim Cournoyer <maxim.cournoyer@gmail.com>
;;; Copyright © 2021-2022 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2021 Xinglu Chen <public@yoctocell.xyz>
;;; Copyright © 2021 Sarah Morgensen <iskarian@mgsn.dev>
;;; Copyright © 2021 Simon Tournier <zimon.toutoune@gmail.com>
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

;;; goproxy protocol:
;;;   https://golang.org/ref/mod#module-proxy
;;;   https://docs.gomods.io/intro/protocol/
;;;   https://roberto.selbach.ca/go-proxies/

(define-module (guix import go)
  #:use-module (git)
  #:use-module (git structs)
  #:use-module (git errors)
  #:use-module (guix build-system go)
  #:use-module (guix git)
  #:use-module (guix hash)
  #:use-module (guix i18n)
  #:use-module (guix diagnostics)
  #:use-module (guix import utils)
  #:use-module (guix import json)
  #:use-module (guix packages)
  #:use-module ((guix utils) #:select (string-replace-substring))
  ;; FIXME? We use a local copy of http-fetch.
  ;; See https://issues.guix.gnu.org/54836
  #:use-module ((guix http-client) #:hide (http-fetch))
  #:use-module (guix base64)
  #:use-module (rnrs bytevectors)
  #:use-module ((guix build download)
                #:select (open-socket-for-uri
                          (open-connection-for-uri
                           . guix:open-connection-for-uri)
                          resolve-uri-reference))
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix memoization)
  #:autoload   (htmlprag) (html->sxml)            ;from Guile-Lib
  #:autoload   (guix serialization) (write-file)
  #:autoload   (guix base32) (bytevector->nix-base32-string)
  #:autoload   (guix build utils) (mkdir-p dump-port)
  #:autoload   (gcrypt hash) (hash-algorithm sha256)
  #:use-module (ice-9 format)
  #:use-module (ice-9 control)
  #:use-module (ice-9 exceptions)
  #:use-module (ice-9 match)
  #:use-module (ice-9 peg)
  #:use-module (ice-9 rdelim)
  #:use-module (ice-9 receive)
  #:use-module (ice-9 regex)
  #:use-module (ice-9 textual-ports)
  #:use-module ((rnrs io ports) #:select (call-with-port))
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-2)
  #:use-module (srfi srfi-9)
  #:use-module (srfi srfi-11)
  #:use-module (srfi srfi-26)
  #:use-module (srfi srfi-34)
  #:use-module (srfi srfi-35)
  #:use-module (sxml match)
  #:use-module ((sxml xpath) #:renamer (lambda (s)
                                         (if (eq? 'filter s)
                                             'xfilter
                                             s)))
  #:use-module (web client)
  #:use-module (web response)
  #:use-module (web uri)

  #:export (go-module->guix-package
            go-module->guix-package*
            go-module-recursive-import))

;; This is a duplicate from (guix http-client) with the addition of a
;; #:accept-all-response-codes? param. See https://issues.guix.gnu.org/54836
(define* (http-fetch uri #:key port (text? #f) (buffered? #t)
                     (open-connection guix:open-connection-for-uri)
                     (keep-alive? #f)
                     (verify-certificate? #t)
                     (headers '((user-agent . "GNU Guile")))
                     (log-port (current-error-port))
                     timeout
                     (accept-all-response-codes? #f))
  "Return an input port containing the data at URI, and the expected number of
bytes available or #f.  If TEXT? is true, the data at URI is considered to be
textual.  Follow any HTTP redirection.  When BUFFERED? is #f, return an
unbuffered port, suitable for use in `filtered-port'.  HEADERS is an alist of
extra HTTP headers.

When KEEP-ALIVE? is true, the connection is marked as 'keep-alive' and PORT is
not closed upon completion.

When VERIFY-CERTIFICATE? is true, verify HTTPS server certificates.

TIMEOUT specifies the timeout in seconds for connection establishment; when
TIMEOUT is #f, connection establishment never times out.

Write information about redirects to LOG-PORT.

When ACCEPT-ALL-RESPONSE-CODES? is false then raise an '&http-get-error'
condition if downloading fails, otherwise return the response regardless
of the reponse code."
  (define parsed-initial-uri
    (if (string? uri) (string->uri uri) uri))

  (define (open-connection* uri)
    (open-connection uri
                     #:verify-certificate? verify-certificate?
                     #:timeout timeout))

  (let loop ((current-uri parsed-initial-uri)
             (current-port (or port (open-connection parsed-initial-uri))))
    (let ((headers (match (uri-userinfo current-uri)
                     ((? string? str)
                      (cons (cons 'Authorization
                                  (string-append "Basic "
                                                 (base64-encode
                                                  (string->utf8 str))))
                            headers))
                     (_ headers))))
      (unless (or buffered? (not (file-port? current-port)))
        (setvbuf current-port 'none))
      (let*-values (((resp data)
                     (http-get current-uri #:streaming? #t #:port current-port
                               #:keep-alive? keep-alive?
                               #:headers headers))
                    ((code)
                     (response-code resp)))
        (case code
          ((200)
           (values data (response-content-length resp)))
          ((301                         ; moved permanently
            302                         ; found (redirection)
            303                         ; see other
            307                         ; temporary redirection
            308)                        ; permanent redirection
           (let ((host (uri-host current-uri))
                 (new-uri (resolve-uri-reference (response-location resp)
                                                 current-uri)))
             (if keep-alive?
                 (dump-port data (%make-void-port "w0")
                            (response-content-length resp))
                 (close-port current-port))
             (format log-port (G_ "following redirection to `~a'...~%")
                     (uri->string new-uri))
             (loop new-uri
                   (or (and keep-alive?
                            (or (not (uri-host new-uri))
                                (string=? host (uri-host new-uri)))
                            current-port)
                       (open-connection* new-uri)))))
          (else
           (if accept-all-response-codes?
               (values data (response-content-length resp))
               (raise (condition (&http-get-error
                                  (uri current-uri)
                                  (code code)
                                  (reason (response-reason-phrase resp))
                                  (headers (response-headers resp)))
                                 (&message
                                  (message
                                   (format
                                    #f
                                    (G_ "~a: HTTP download failed: ~a (~s)")
                                    (uri->string current-uri) code
                                    (response-reason-phrase resp)))))))))))))

;;; Commentary:
;;;
;;; (guix import go) attempts to make it easier to create Guix package
;;; declarations for Go modules.
;;;
;;; Modules in Go are a "collection of related Go packages" which are "the
;;; unit of source code interchange and versioning".  Modules are generally
;;; hosted in a repository.
;;;
;;; At this point it should handle correctly modules which have only Go
;;; dependencies and are accessible from proxy.golang.org (or configured via
;;; GOPROXY).
;;;
;;; We want it to work more or less this way:
;;; - get latest version for the module from GOPROXY
;;; - infer VCS root repo from which we will check-out source by
;;;   + recognising known patterns (like github.com)
;;;   + or recognizing .vcs suffix
;;;   + or parsing meta tag in HTML served at the URL
;;;   + or (TODO) if nothing else works by using zip file served by GOPROXY
;;; - get go.mod from GOPROXY (which is able to synthetize one if needed)
;;; - extract list of dependencies from this go.mod
;;;
;;; The Go module paths are translated to a Guix package name under the
;;; assumption that there will be no collision.

;;; TODO list
;;; - get correct hash in vcs->origin for Mercurial and Subversion

;;; Code:

;; FIXME set up logging for the entire project, and replace this poor man's
;; logger with the proper one.
(define-syntax-rule (log.info format-string ...)
  (let ((port (current-warning-port)))
    (format port format-string ...)
    (newline port)))

(define-syntax-rule (log.debug format-string ...)
  ;;(log.info format-string ...)
  '())

(define http-fetch*
  ;; Like http-fetch, but memoized and returning the body as a string.
  (memoize (lambda args
             (call-with-port (apply http-fetch args) get-string-all))))

(define json-fetch*
  (memoize json-fetch))

(define (go-path-escape path)
  "Escape a module path by replacing every uppercase letter with an
exclamation mark followed with its lowercase equivalent, as per the module
Escaped Paths specification (see:
https://godoc.org/golang.org/x/mod/module#hdr-Escaped_Paths)."
  (define (escape occurrence)
    (string-append "!" (string-downcase (match:substring occurrence))))
  (regexp-substitute/global #f "[A-Z]" path 'pre escape 'post))

;; Prevent inlining of this procedure, which is accessed by unit tests.
(set! go-path-escape go-path-escape)

(define (pkg.go.dev-info module-path)
  ;; FIXME if MODULE-PATH is a fork on github, then it will try to get the
  ;; info of the fork (instead of the upstream), which most probably does not
  ;; exist in pkg.go.dev.  Example: https://github.com/bonitoo-io/oapi-codegen
  (http-fetch* (string-append "https://pkg.go.dev/" module-path)))

(define* (go-module-version-string goproxy name #:key version)
  "Fetch the version string of the latest version for NAME from the given
GOPROXY server, or for VERSION when specified."
  (let ((file (if version
                  (string-append "@v/" version ".info")
                  "@latest")))
    (assoc-ref (json-fetch* (format #f "~a/~a/~a"
                                    goproxy (go-path-escape name) file))
               "Version")))

(define* (go-module-available-versions goproxy name)
  "Retrieve the available versions for a given module from the module proxy.
Versions are being returned **unordered** and may contain different versioning
styles for the same package."
  (let* ((url (string-append goproxy "/" (go-path-escape name) "/@v/list"))
         (body (http-fetch* url))
         (versions (remove string-null? (string-split body #\newline))))
    (if (null? versions)
        (list (go-module-version-string goproxy name)) ;latest version
        versions)))

(define (go-package-licenses name)
  "Retrieve the list of licenses that apply to NAME, a Go package or module
name (e.g. \"github.com/golang/protobuf/proto\")."
  (let* ((body (pkg.go.dev-info (string-append name "?tab=licenses")))
         ;; Extract the text contained in a h2 child node of any
         ;; element marked with a "License" class attribute.
         (select (sxpath `(// (* (@ (equal? (class "License"))))
                              h2 // div // *text*))))
    (select (html->sxml body #:strict? #t))))

(define (sxml->texi sxml-node)
  "A very basic SXML to Texinfo converter which attempts to preserve HTML
formatting and links as text."
  (sxml-match sxml-node
    ((strong ,text)
     (format #f "@strong{~a}" text))
    ((a (@ (href ,url)) ,body)
     ;; Examples: image in the url: github.com/go-openapi/jsonpointer
     ;; (code ...) in the URL body: github.com/mwitkow/go-conntrack
     (if (string? body)
         (format #f "@url{~a,~a}" url body)
         (sxml-match body
                     ((code ,text)
                      (format #f "@url{~a,~a}" url (sxml->texi body)))
                     (,_
                      (format #f "@url{~a}" url)))))
    ((code ,text)
     (format #f "@code{~a}" text))
    (,something-else
     ;; Example: @ in the description: github.com/ethersphere/langos
     (if (string? something-else)
         (string-replace-substring something-else
                                   "@" "@@")
         something-else))))

(define (go-package-description name)
  "Retrieve a short description for NAME, a Go package name,
e.g. \"google.golang.org/protobuf/proto\"."
  (let* ((body (pkg.go.dev-info name))
         (sxml (html->sxml body #:strict? #t))
         (overview ((sxpath
                     `(//
                       (* (@ (equal? (class "Documentation-overview"))))
                       (p 1))) sxml))
         ;; Sometimes, the first paragraph just contains images/links that
         ;; has only "\n" for text.  The following filter is designed to
         ;; omit it.
         (contains-text? (lambda (node)
                           (remove string-null?
                                   (map string-trim-both
                                        (filter (node-typeof? '*text*)
                                                (cdr node))))))
         (select-content (sxpath
                          `(//
                            (* (@ (equal? (class "UnitReadme-content"))))
                            div // p ,(xfilter contains-text?))))
         ;; Fall-back to use content; this is less desirable as it is more
         ;; verbose, but not every page has an overview.
         (description (if (not (null? overview))
                          overview
                          (select-content sxml)))
         (description* (if (not (null? description))
                           (first description)
                           description)))
    (match description*
      (() #f)                           ;nothing selected
      ((p elements ...)
       (apply string-append (filter string? (map sxml->texi elements)))))))

(define (go-package-synopsis module-name)
  "Retrieve a short synopsis for a Go module named MODULE-NAME,
e.g. \"google.golang.org/protobuf\".  The data is scraped from
the https://pkg.go.dev/ web site."
  ;; Note: Only the *module* (rather than package) page has the README title
  ;; used as a synopsis on the https://pkg.go.dev web site.
  (let* ((body (pkg.go.dev-info module-name))
         ;; Extract the text contained in a h2 child node of any
         ;; element marked with a "License" class attribute.
         (select-title (sxpath
                        `(// (div (@ (equal? (class "UnitReadme-content"))))
                             // h3 *text*))))
    (match (select-title (html->sxml body #:strict? #t))
      (() #f)                           ;nothing selected
      ((title more ...)                 ;title is the first string of the list
       (string-trim-both title)))))

(define (list->licenses licenses)
  "Given a list of LICENSES mostly following the SPDX conventions, return the
corresponding Guix license or 'unknown-license!"
  (filter-map (lambda (license)
                (and (not (string-null? license))
                     (not (any (cut string=? <> license)
                               '("AND" "OR" "WITH")))
                     ;; Adjust the license names scraped from
                     ;; https://pkg.go.dev to an equivalent SPDX identifier,
                     ;; if they differ (see: https://github.com/golang/pkgsite
                     ;; /internal/licenses/licenses.go#L174).
                     (or (spdx-string->license
                          (match license
                            ("BlueOak-1.0" "BlueOak-1.0.0")
                            ("BSD-0-Clause" "0BSD")
                            ("BSD-2-Clause" "BSD-2-Clause-FreeBSD")
                            ("GPL2" "GPL-2.0")
                            ("GPL3" "GPL-3.0")
                            ("NIST" "NIST-PD")
                            (_ license)))
                         'unknown-license!)))
              licenses))

(define (fetch-go.mod goproxy module-path version)
  "Fetch go.mod from the given GOPROXY server for the given MODULE-PATH
and VERSION and return an input port."
  (let ((url (format #f "~a/~a/@v/~a.mod" goproxy
                     (go-path-escape module-path)
                     (go-path-escape version))))
    (http-fetch* url)))


(define (parse-go.mod content)
  "Parse the go.mod file CONTENT, returning a list of directives, comments,
and unknown lines.  Each sublist begins with a symbol (go, module, require,
replace, exclude, retract, comment, or unknown) and is followed by one or more
sublists.  Each sublist begins with a symbol (module-path, version, file-path,
comment, or unknown) and is followed by the indicated data."
  ;; https://golang.org/ref/mod#go-mod-file-grammar
  (define-peg-pattern NL none "\n")
  (define-peg-pattern WS none (or " " "\t" "\r"))
  (define-peg-pattern => none (and (* WS) "=>"))
  (define-peg-pattern punctuation none (or "," "=>" "[" "]" "(" ")"))
  (define-peg-pattern comment all
    (and (ignore "//") (* WS) (* (and (not-followed-by NL) peg-any))))
  (define-peg-pattern EOL body (and (* WS) (? comment) NL))
  (define-peg-pattern block-start none (and (* WS) "(" EOL))
  (define-peg-pattern block-end none (and (* WS) ")" EOL))
  (define-peg-pattern any-line body
    (and (* WS) (* (and (not-followed-by NL) peg-any)) EOL))

  ;; Strings and identifiers
  (define-peg-pattern identifier body
    (+ (and (not-followed-by (or NL WS punctuation)) peg-any)))
  (define-peg-pattern string-raw body
    (and (ignore "`") (+ (and (not-followed-by "`") peg-any)) (ignore "`")))
  (define-peg-pattern string-quoted body
    (and (ignore "\"")
         (+ (or (and (ignore "\\") peg-any)
                (and (not-followed-by "\"") peg-any)))
         (ignore "\"")))
  (define-peg-pattern string-or-ident body
    (and (* WS) (or string-raw string-quoted identifier)))

  (define-peg-pattern version all string-or-ident)
  (define-peg-pattern module-path all string-or-ident)
  (define-peg-pattern file-path all string-or-ident)

  ;; Non-directive lines
  (define-peg-pattern unknown all any-line)
  (define-peg-pattern block-line body
    (or EOL (and (not-followed-by block-end) unknown)))

  ;; GoDirective = "go" GoVersion newline .
  (define-peg-pattern go all (and (ignore "go") version EOL))

  ;; ModuleDirective = "module" ( ModulePath | "(" newline ModulePath newline ")" ) newline .
  (define-peg-pattern module all
    (and (ignore "module") (or (and block-start module-path EOL block-end)
                               (and module-path EOL))))

  ;; The following directives may all be used solo or in a block
  ;; RequireSpec = ModulePath Version newline .
  (define-peg-pattern require all (and module-path version EOL))
  (define-peg-pattern require-top body
    (and (ignore "require")
         (or (and block-start (* (or require block-line)) block-end) require)))

  ;; ExcludeSpec = ModulePath Version newline .
  (define-peg-pattern exclude all (and module-path version EOL))
  (define-peg-pattern exclude-top body
    (and (ignore "exclude")
         (or (and block-start (* (or exclude block-line)) block-end) exclude)))

  ;; ReplaceSpec = ModulePath [ Version ] "=>" FilePath newline
  ;;             | ModulePath [ Version ] "=>" ModulePath Version newline .
  (define-peg-pattern original all (or (and module-path version) module-path))
  (define-peg-pattern with all (or (and module-path version) file-path))
  (define-peg-pattern replace all (and original => with EOL))
  (define-peg-pattern replace-top body
    (and (ignore "replace")
         (or (and block-start (* (or replace block-line)) block-end) replace)))

  ;; RetractSpec = ( Version | "[" Version "," Version "]" ) newline .
  (define-peg-pattern range all
    (and (* WS) (ignore "[") version
         (* WS) (ignore ",") version (* WS) (ignore "]")))
  (define-peg-pattern retract all (and (or range version) EOL))
  (define-peg-pattern retract-top body
    (and (ignore "retract")
         (or (and block-start (* (or retract block-line)) block-end) retract)))

  (define-peg-pattern go-mod body
    (* (and (* WS) (or go module require-top exclude-top replace-top
                       retract-top EOL unknown))))

  (let ((tree (peg:tree (match-pattern go-mod content)))
        (keywords '(go module require replace exclude retract comment unknown)))
    (keyword-flatten keywords tree)))

;; Prevent inlining of this procedure, which is accessed by unit tests.
(set! parse-go.mod parse-go.mod)

(define (go.mod-directives go.mod directive)
  "Return the list of top-level directive bodies in GO.MOD matching the symbol
DIRECTIVE."
  (filter-map (match-lambda
                (((? (cut eq? <> directive) head) . rest) rest)
                (_ #f))
              go.mod))

(define (go.mod-requirements go.mod)
  "Compute and return the list of requirements specified by GO.MOD."
  (define (replace directive requirements)
    ;; Specification: https://golang.org/ref/mod#go-mod-file-replace
    ;; Interesting test cases:
    ;;   github.com/influxdata/influxdb-client-go/v2@v2.4.0
    (log.debug "inside replace, directive ~S, requirements ~S" directive requirements)
    (define (maybe-replace old-module-path old-version new-module-path new-version)
      (let ((matched-entry (assoc-ref requirements old-module-path)))
        (log.debug "inside maybe-replace, ~S ~S => ~S ~S, matched-entry ~S"
                   old-module-path old-version new-module-path new-version matched-entry)
        (cond ((and (equal? old-module-path new-module-path)
                    (not matched-entry))
               ;; "A replace directive has no effect if the module version on the left
               ;; side is not required."
               ;; Do not allow version updates for indirect dependencies.
               requirements)
              ((and matched-entry
                    (or (not old-version)
                        (equal? old-version new-version)))
               (cons (list new-module-path new-version)
                     (alist-delete old-module-path requirements)))
              (else
               requirements))))
    (log.debug "toplevel directive is ~S" directive)
    (match directive
      ((('original ('module-path old-module-path) ('version old-version) ...) with)
       (unless (null? old-version)
         (set! old-version (first old-version)))
       (match with
         (('with ('file-path _))
          ;; Superseded by a module in a local path, so let's delete it.
          (alist-delete old-module-path requirements))
         (('with ('module-path new-module-path) ('version new-version))
          (maybe-replace old-module-path old-version
                         new-module-path new-version))))))

  (define (require directive requirements)
    (match directive
      ((('module-path module-path) ('version version) . _)
       (cons (list module-path version) requirements))))

  (let* ((requires (go.mod-directives go.mod 'require))
         (replaces (go.mod-directives go.mod 'replace))
         (requirements (fold require '() requires))
         (result (fold replace requirements replaces)))
    (log.debug "requires:~% ~S~%replaces:~% ~S~%result:~% ~S" requires replaces result)
    result))

;; Prevent inlining of this procedure, which is accessed by unit tests.
(set! go.mod-requirements go.mod-requirements)

(define-record-type <vcs>
  (%make-vcs url-prefix root-regex type)
  vcs?
  (url-prefix vcs-url-prefix)
  (root-regex vcs-root-regex)
  (type vcs-type))

(define (make-vcs prefix regexp type)
  (%make-vcs prefix (make-regexp regexp) type))

(define known-vcs
  ;; See the following URL for the official Go equivalent:
  ;; https://github.com/golang/go/blob/846dce9d05f19a1f53465e62a304dea21b99f910/src/cmd/go/internal/vcs/vcs.go#L1026-L1087
  (list
   (make-vcs
    "github.com"
    "^(github\\.com/[A-Za-z0-9_.\\-]+/[A-Za-z0-9_.\\-]+)(/[A-Za-z0-9_.\\-]+)*$"
    'git)
   (make-vcs
    "bitbucket.org"
    "^(bitbucket\\.org/([A-Za-z0-9_.\\-]+/[A-Za-z0-9_.\\-]+))(/[A-Za-z0-9_.\\-]+)*$"
    'unknown)
   (make-vcs
    "hub.jazz.net/git/"
    "^(hub\\.jazz\\.net/git/[a-z0-9]+/[A-Za-z0-9_.\\-]+)(/[A-Za-z0-9_.\\-]+)*$"
    'git)
   (make-vcs
    "git.apache.org"
    "^(git\\.apache\\.org/[a-z0-9_.\\-]+\\.git)(/[A-Za-z0-9_.\\-]+)*$"
    'git)
   (make-vcs
    "git.openstack.org"
    "^(git\\.openstack\\.org/[A-Za-z0-9_.\\-]+/[A-Za-z0-9_.\\-]+)(\\.git)?\
(/[A-Za-z0-9_.\\-]+)*$"
    'git)))

(define (module-path->repository-root module-path)
  "Infer the repository root from a module path.  Go modules can be
defined at any level of a repository tree, but querying for the meta tag
usually can only be done from the web page at the root of the repository,
hence the need to derive this information."

  ;; For reference, see: https://golang.org/ref/mod#vcs-find.
  (define vcs-qualifiers '(".bzr" ".fossil" ".git" ".hg" ".svn"))

  (define (vcs-qualified-module-path->root-repo-url module-path)
    (let* ((vcs-qualifiers-group (string-join vcs-qualifiers "|"))
           (pattern (format #f "^(.*(~a))(/|$)" vcs-qualifiers-group))
           (m (string-match pattern module-path)))
      (and=> m (cut match:substring <> 1))))

  (or (and=> (find (lambda (vcs)
                     (string-prefix? (vcs-url-prefix vcs) module-path))
                   known-vcs)
             (lambda (vcs)
               (match:substring (regexp-exec (vcs-root-regex vcs)
                                             module-path) 1)))
      (vcs-qualified-module-path->root-repo-url module-path)
      module-path))

(define* (go-module->guix-package-name module-path #:optional version)
  "Converts a module's path to the canonical Guix format for Go packages.
Optionally include a VERSION string to append to the name."
  ;; Map dot, slash, underscore and tilde characters to hyphens.
  (let ((module-path* (string-map (lambda (c)
                                    (if (member c '(#\. #\/ #\_ #\~))
                                        #\-
                                        c))
                                  module-path)))
    (string-downcase (string-append "go-" module-path*
                                    (if version
                                        (string-append "-" version)
                                        "")))))

(define (strip-.git-suffix/maybe repo-url)
  "Strip a repository URL '.git' suffix from REPO-URL if hosted at GitHub."
  (match repo-url
    ((and (? (cut string-prefix? "https://github.com" <>))
          (? (cut string-suffix? ".git" <>)))
     (string-drop-right repo-url 4))
    (_ repo-url)))

(define-record-type <module-meta>
  (make-module-meta import-prefix vcs repo-root)
  module-meta?
  (import-prefix module-meta-import-prefix)
  (vcs module-meta-vcs)                 ;a symbol
  (repo-root module-meta-repo-root))

(define (fetch-module-meta-data module-path)
  "Retrieve the module meta-data from its landing page.  This is necessary
because goproxy servers don't currently provide all the information needed to
build a package."
  (define (go-import->module-meta content-text)
    (match (string-tokenize content-text char-set:graphic)
      ((root-path vcs repo-url)
       (make-module-meta root-path (string->symbol vcs)
                         (strip-.git-suffix/maybe repo-url)))))
  ;; <meta name="go-import" content="import-prefix vcs repo-root">
  (let* ((url (format #f "https://~a?go-get=1" module-path))
         (meta-data (http-fetch* url #:accept-all-response-codes? #true))
         (select (sxpath `(// (meta (@ (equal? (name "go-import"))))
                              // content)))
         (sxml (html->sxml meta-data #:strict? #t))
         (selected (select sxml)))
    (log.debug "The fetched meta-data from ~A is:~%~S" url selected)
    (match selected
      (() #f)                           ;nothing selected
      ((('content content-text) ..1)
       (or
        (find (lambda (meta)
                (string-prefix? (module-meta-import-prefix meta) module-path))
              (map go-import->module-meta content-text))
        ;; Fallback to the first meta if no import prefixes match.
        (go-import->module-meta (first content-text)))))))

(define (module-meta-data-repo-url meta-data goproxy)
  "Return the URL where the fetcher which will be used can download the
source."
  (if (member (module-meta-vcs meta-data) '(fossil mod))
      goproxy
      (module-meta-repo-root meta-data)))

(define* (git-checkout-hash url reference algorithm)
  "Return the ALGORITHM hash of the checkout of URL at REFERENCE, a commit or
tag."
  (define cache
    (string-append (or (getenv "TMPDIR") "/tmp")
                   "/guix-import-go-"
                   (passwd:name (getpwuid (getuid)))))

  ;; Use a custom cache to avoid cluttering the default one under
  ;; ~/.cache/guix, but choose one under /tmp so that it's persistent across
  ;; subsequent "guix import" invocations.
  (mkdir-p cache)
  (chmod cache #o700)
  (let-values (((checkout commit _)
                (parameterize ((%repository-cache-directory cache))
                  (update-cached-checkout url
                                          #:ref
                                          `(tag-or-commit . ,reference)))))
    (file-hash* checkout #:algorithm algorithm #:recursive? #true)))

(define (vcs->origin vcs-type vcs-repo-url version)
  "Generate the `origin' block of a package depending on what type of source
control system is being used."
  (case vcs-type
    ((git)
     (let ((plain-version? (string=? version (go-version->git-ref version)))
           (v-prefixed?    (string-prefix? "v" version)))
       `(origin
          (method git-fetch)
          (uri (git-reference
                (url ,vcs-repo-url)
                ;; This is done because the version field of the package,
                ;; which the generated quoted expression refers to, has been
                ;; stripped of any 'v' prefixed.
                (commit ,(if (and plain-version? v-prefixed?)
                             '(string-append "v" version)
                             '(go-version->git-ref version)))))
          (file-name (git-file-name name version))
          (sha256
           (base32
            ,(bytevector->nix-base32-string
              (git-checkout-hash vcs-repo-url (go-version->git-ref version)
                                 (hash-algorithm sha256))))))))
    ((hg)
     `(origin
        (method hg-fetch)
        (uri (hg-reference
              (url ,vcs-repo-url)
              (changeset ,version)))
        (file-name (string-append name "-" version "-checkout"))
        (sha256
         (base32
          ;; FIXME: populate hash for hg repo checkout
          "0000000000000000000000000000000000000000000000000000"))))
    ((svn)
     `(origin
        (method svn-fetch)
        (uri (svn-reference
              (url ,vcs-repo-url)
              (revision (string->number version))))
        (file-name (string-append name "-" version "-checkout"))
        (sha256
         (base32
          ;; FIXME: populate hash for svn repo checkout
          "0000000000000000000000000000000000000000000000000000"))))
    (else
     (raise
      (formatted-message (G_ "unsupported vcs type '~a' for package '~a'")
                         vcs-type vcs-repo-url)))))

(define (strip-v-prefix version)
  "Strip from VERSION the \"v\" prefix that Go uses."
  (string-trim version #\v))

(define (ensure-v-prefix version)
  "Add a \"v\" prefix to VERSION if it does not already have one."
  (if (string-prefix? "v" version)
      version
      (string-append "v" version)))

(define (validate-version version available-versions module-path)
  "Raise an error if VERSION is not among AVAILABLE-VERSIONS, unless VERSION
is a pseudo-version.  Return VERSION."
  ;; Pseudo-versions do not appear in the versions list; skip the
  ;; following check.
  (if (or (go-pseudo-version? version)
          (member version available-versions))
      version
      (raise
       (make-compound-condition
        (formatted-message (G_ "version ~a of ~a is not available~%")
                           version module-path available-versions)
        (condition (&fix-hint
                    (hint (format #f (G_ "Pick one of the following \
available versions:~{ ~a~}.")
                                  (map strip-v-prefix
                                       available-versions)))))))))

(define* (go-module->guix-package module-path #:key
                                  (goproxy "https://proxy.golang.org")
                                  version
                                  pin-versions?)
  "Return the package S-expression corresponding to MODULE-PATH at VERSION, a Go package.
The meta-data is fetched from the GOPROXY server and https://pkg.go.dev/.
When VERSION is unspecified, the latest version available is used."
  (let* ((available-versions (go-module-available-versions goproxy module-path))
         (version* (validate-version
                    (or (and version (ensure-v-prefix version))
                        (go-module-version-string goproxy module-path)) ;latest
                    available-versions
                    module-path))
         (content (fetch-go.mod goproxy module-path version*))
         (dependencies+versions (go.mod-requirements (parse-go.mod content)))
         (dependencies (if pin-versions?
                           dependencies+versions
                           (map car dependencies+versions)))
         (module-path-sans-suffix
          (match:prefix (string-match "([\\./]v[0-9]+)?$" module-path)))
         (guix-name (go-module->guix-package-name module-path))
         (root-module-path (module-path->repository-root module-path))
         ;; The VCS type and URL are not included in goproxy information. For
         ;; this we need to fetch it from the official module page.
         (meta-data (fetch-module-meta-data root-module-path))
         (vcs-type (module-meta-vcs meta-data))
         (vcs-repo-url (module-meta-data-repo-url meta-data goproxy))
         (synopsis (go-package-synopsis module-path))
         (description (go-package-description module-path))
         (licenses (go-package-licenses module-path)))
    (values
     `(package
        (name ,guix-name)
        (version ,(strip-v-prefix version*))
        (source
         ,(vcs->origin vcs-type vcs-repo-url version*))
        (build-system go-build-system)
        (arguments
         '(#:import-path ,module-path
           ,@(if (string=? module-path-sans-suffix root-module-path)
                 '()
                 `(#:unpack-path ,root-module-path))))
        ,@(maybe-propagated-inputs
           (map (match-lambda
                  ((name version)
                   (go-module->guix-package-name name (strip-v-prefix version)))
                  (name
                   (go-module->guix-package-name name)))
                dependencies))
        (home-page ,(format #f "https://~a" root-module-path))
        (synopsis ,synopsis)
        (description ,(and=> description beautify-description))
        (license ,(match (list->licenses licenses)
                    (() #f)                       ;unknown license
                    ((license)                    ;a single license
                     license)
                    ((license ...)                ;a list of licenses
                     `(list ,@license)))))
     (if pin-versions?
         dependencies+versions
         dependencies))))

(define (go-module->guix-package* . args)
  ;; Disable output buffering so that the following warning gets printed
  ;; consistently.
  (setvbuf (current-error-port) 'none)
  (setvbuf (current-warning-port) 'none)
  (let* ((package-name (match args ((name _ ...) name)))
         ;; Use report-all-errors? for debugging purposes only, because
         ;; e.g. getaddrinfo is not reentrant and therefore we must unwind
         ;; before retrying.
         (report-all-errors? #false)
         (report-network-error
          (lambda (reason)
            (warning (G_ "Failing to import package ~S.
reason: ~A.~%")
                     package-name reason))))
    (let loop ((attempts 0))
      (when (> attempts 0)
        (sleep 3)
        (log.info "~%Retrying, attempt ~s." attempts))
      (cond
       ((> attempts 60)
        (warning (G_ "Giving up on importing package ~s.
This package and its dependencies won't be imported.~%")
                 package-name)
        (values #f '()))
       (else
        (guard (c ((http-get-error? c)
                   (report-network-error
                    (format #f "~s could not be fetched: HTTP error ~a (~s)"
                            (uri->string (http-get-error-uri c))
                            (http-get-error-code c)
                            (http-get-error-reason c)))
                   (loop (+ 1 attempts)))
                  ((eq? (exception-kind c)
                        'getaddrinfo-error)
                   (report-network-error "DNS lookup failed")
                   (loop (+ 1 attempts)))
                  ((and (eq? (exception-kind c)
                             'git-error)
                        (eq? (git-error-class (first (exception-args c)))
                             GITERR_NET))
                   (report-network-error "network error coming from git")
                   (loop (+ 1 attempts)))
                  (else
                   (let ((port (current-warning-port)))
                     (format port "Unexpected error, will skip ~S.~%reason: "
                             package-name)
                     ;; Printing a backtrace here is not very useful: it is
                     ;; cut off because GUARD unwinds.
                     (print-exception port (stack-ref (make-stack #t) 1)
                                      c (exception-args c))
                     (display-backtrace (make-stack #t) port))
                   ;; give up on this entry
                   (values #f '())))
          (with-exception-handler
              (lambda (c)
                (when report-all-errors?
                  (let ((port (current-warning-port)))
                    (format port "*** exception while importing:~%")
                    (print-exception port (stack-ref (make-stack #t) 1)
                                     c (exception-args c))
                    (format port "*** printing backtrace:~%")
                    (display-backtrace (make-stack #t) port)
                    ;; DISPLAY-BACKTRACE can fail, so it's better to make its
                    ;; exit also visible.
                    (format port "*** done printing backtrace~%")))
                (raise-continuable c))
            (lambda ()
              (apply go-module->guix-package args))
            #:unwind? (not report-all-errors?))))))))

(define* (go-module-recursive-import package-name
                                     #:key (goproxy "https://proxy.golang.org")
                                     version
                                     pin-versions?)

  (recursive-import
   package-name
   #:repo->guix-package
   (memoize
    (lambda* (name #:key version repo)
      (receive (package-sexp dependencies)
          (go-module->guix-package* name #:goproxy goproxy
                                    #:version version
                                    #:pin-versions? pin-versions?)
        (values package-sexp dependencies))))
   #:guix-name go-module->guix-package-name
   #:version version))
