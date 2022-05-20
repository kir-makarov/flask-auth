CREATE TABLE public.users (
	id uuid NOT NULL,
	username text NOT NULL,
	email text NOT NULL,
	password text NOT NULL,
	created timestamptz NULL,
	modified timestamptz NULL,
	CONSTRAINT users_email_key UNIQUE (email),
	CONSTRAINT users_pkey PRIMARY KEY (id)
);