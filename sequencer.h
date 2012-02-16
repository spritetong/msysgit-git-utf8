#ifndef SEQUENCER_H
#define SEQUENCER_H

#define SEQ_DIR		"sequencer"
#define SEQ_HEAD_FILE	"sequencer/head"
#define SEQ_TODO_FILE	"sequencer/todo"
#define SEQ_OPTS_FILE	"sequencer/opts"

enum replay_action {
	REPLAY_REVERT,
	REPLAY_PICK
};

enum replay_subcommand {
	REPLAY_NONE,
	REPLAY_REMOVE_STATE,
	REPLAY_CONTINUE,
	REPLAY_ROLLBACK
};

struct replay_opts {
	enum replay_action action;
	enum replay_subcommand subcommand;

	/* Boolean options */
	int edit;
	int record_origin;
	int no_commit;
	int signoff;
	int allow_ff;
	int allow_rerere_auto;

	int mainline;

	/* Merge strategy */
	const char *strategy;
	const char **xopts;
	size_t xopts_nr, xopts_alloc;

	/* Only used by REPLAY_NONE */
	struct rev_info *revs;
};

/* Removes SEQ_DIR. */
extern void remove_sequencer_state(void);

int sequencer_pick_revisions(struct replay_opts *opts);

#endif
