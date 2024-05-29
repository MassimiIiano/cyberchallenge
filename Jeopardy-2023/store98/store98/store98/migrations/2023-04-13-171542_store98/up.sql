CREATE TABLE IF NOT EXISTS users (
	id INTEGER NOT NULL AUTO_INCREMENT,
	username TEXT UNIQUE NOT NULL,
	password TEXT NOT NULL,
	token TEXT,
	PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS products (
	id INTEGER NOT NULL AUTO_INCREMENT,
	price INTEGER NOT NULL,
	name TEXT NOT NULL,
	description TEXT NOT NULL,
	image_src TEXT NOT NULL,
	image_credits TEXT NOT NULL,
	PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS csrftokens (
	id INTEGER NOT NULL AUTO_INCREMENT,
	token TEXT NOT NULL,
	PRIMARY KEY (id)
);

INSERT INTO
	products (
		name,
		description,
		image_src,
		image_credits,
		price
	)
VALUES
	(
		'Gaming computer',
		'A modern high-powered gaming machine, sold in perfect conditions if not for a couple of scratches caused by moving it around. Monitor and peripherals are not included, but you can contact me for an offer. Refunds not accepted.',
		'https://i.pinimg.com/550x/bd/bb/46/bdbb4612a25bc6d7676cbeab4fb92301.jpg',
		'https://www.pinterest.com/pin/852517404455158131/',
		42069
	),
	(
		'Racing simulator',
		'Complete racing simulator setup, perfect for playing Assetto Corsa, Gran Turismo, Forza, and my personal favorite The Simpsons: Road Rage. The system is equipped with the most recent, most powerful components, ready to play modern games with an average frame count of 420.',
		'https://i.ytimg.com/vi/j_WpEYAAmi8/maxresdefault.jpg',
		'https://www.youtube.com/watch?v=j_WpEYAAmi8',
		133700
	),
	(
		'Professional office machine',
		'This is the perfect machine for an office environment, an inconspicuous, silent, powerful, performant, potent, sturdy, fashionable, stealth, modern, industrial-looking machine, perfect for office task and the occasional in-office gaming, perfect for titles like the glorious Donald Duck: Quack Attack?!',
		'https://i.pinimg.com/originals/36/86/4b/36864b1d542ba50dc034bc5ca5a8d874.jpg',
		'https://www.pinterest.com/pin/10-seriously-bizarre-pc-designs--368661919473860065/',
		4200
	);