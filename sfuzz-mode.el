(defvar sfuzz-mode-hook nil)

(defconst sfuzz-font-lock-keywords
  (list
   '("\\<endcfg\\|ENDCFG\\|literal\\|LITERAL\\|sequence\\|SEQUENCE\\|include\\|INCLUDE\\|maxseqlen\\|MAXSEQLEN\\|seqstep\\|SEQSTEP\\|reqwait\\|REQWAIT\\|plugin\\|PLUGIN\\|FUZZ\\>" . font-lock-builtin-face)
   '("^!.*=" . font-lock-variable-name-face)
   '("^++.*=" . font-lock-variable-name-face)
   '("^$.*=" . font-lock-constant-face)
   '("^#.*" . font-lock-comment-face)
   '("^//.*" . font-lock-comment-face)
   '("^;.*" . font-lock-comment-face)
   )
  "Minimal highlights for sfuzz"
)

(defun sfuzz-mode ()
  "Major mode for editing sfuzz files"
  (interactive)
  (kill-all-local-variables)
  (set (make-local-variable 'font-lock-defaults) '(sfuzz-font-lock-keywords))
  (setq major-mode 'sfuzz-mode)
  (setq mode-name "SimpleFuzz")
  (run-hooks 'sfuzz-mode-hook)
)
(provide 'sfuzz-mode)