CREATE TABLE IF NOT EXISTS `users` (
    `id` VARCHAR(36) NOT NULL,
    `name` TEXT NOT NULL,
    `email` TEXT NOT NULL UNIQUE,
    `password` TEXT NOT NULL,
    PRIMARY KEY (`id`)
);

CREATE TABLE IF NOT EXISTS `saved_cart` (
    `id` INT AUTO_INCREMENT NOT NULL,
    `user` VARCHAR(36) NOT NULL,
    `cart` JSON,
    PRIMARY KEY (`id`),
    FOREIGN KEY (`user`) REFERENCES `users`(`id`)
);

CREATE TABLE IF NOT EXISTS `products` (
    `id` VARCHAR(36) NOT NULL,
    `name` TEXT NOT NULL,
    `description` JSON NOT NULL,
    `short_description` TEXT NOT NULL,
    `price` INT NOT NULL,
    `image` TEXT NOT NULL,
    `order` INT NOT NULL DEFAULT(0),
    PRIMARY KEY (`id`)
);

INSERT INTO
    `products` (
        `id`,
        `name`,
        `description`,
        `short_description`,
        `price`,
        `image`,
        `order`
    )
VALUES
    (
        'minecclicker',
        'minecclicker',
        '["Introducing our High-Quality Vinyl Stickers, crafted with meticulous attention to detail and exceptional durability. Express your unique style and personalize your belongings with ease using our adhesive works of art.", "Made from premium materials, these stickers resist fading, scratching, and water damage, ensuring long-lasting vibrancy on any surface. The versatile adhesive backing allows for easy application and repositioning, leaving no residue behind.", "Join us in our commitment to sustainability with our environmentally friendly materials and production processes."]',
        'Premium vinyl sticker',
        100,
        '/minecclicker.svg',
        1
    ),
    (
        'gabibbi-towers',
        'Gabibbi Towers',
        '["Introducing our High-Quality Vinyl Stickers, crafted with meticulous attention to detail and exceptional durability. Express your unique style and personalize your belongings with ease using our adhesive works of art.", "Made from premium materials, these stickers resist fading, scratching, and water damage, ensuring long-lasting vibrancy on any surface. The versatile adhesive backing allows for easy application and repositioning, leaving no residue behind.", "Join us in our commitment to sustainability with our environmentally friendly materials and production processes."]',
        'Premium vinyl sticker',
        100,
        '/gabibbi-towers.svg',
        1
    ),
    (
        'cyberchallenge',
        'CyberChallenge.IT',
        '["Introducing our High-Quality Vinyl Stickers, crafted with meticulous attention to detail and exceptional durability. Express your unique style and personalize your belongings with ease using our adhesive works of art.", "Made from premium materials, these stickers resist fading, scratching, and water damage, ensuring long-lasting vibrancy on any surface. The versatile adhesive backing allows for easy application and repositioning, leaving no residue behind.", "Join us in our commitment to sustainability with our environmentally friendly materials and production processes."]',
        'Premium vinyl sticker',
        150,
        '/cc.svg',
        2
    );

CREATE TABLE IF NOT EXISTS `base_custom_product` (
    `id` VARCHAR(36) NOT NULL,
    `name` TEXT NOT NULL,
    `description` JSON NOT NULL,
    `price` INT NOT NULL,
    `image` TEXT NOT NULL,
    `order` INT NOT NULL DEFAULT(0),
    PRIMARY KEY (`id`)
);

INSERT INTO
    `base_custom_product` (
        `id`,
        `name`,
        `description`,
        `price`,
        `image`,
        `order`
    )
VALUES
    (
        'custom-sticker',
        'Custom sticker',
        '["Introducing custom stickers! The same as our High-Quality Vinyl Stickers, crafted with meticulous attention to detail and exceptional durability, but with your graphics on it!", "Made from premium materials, these stickers resist fading, scratching, and water damage, ensuring long-lasting vibrancy on any surface. The versatile adhesive backing allows for easy application and repositioning, leaving no residue behind.", "Join us in our commitment to sustainability with our environmentally friendly materials and production processes."]',
        200,
        '/custom.svg',
        1
    ),
    (
        'custom-shirt',
        'Printed Cotton T-Shirt',
        '["Introducing our Printed Cotton T-Shirt, where style meets comfort. Crafted from premium cotton, it offers a soft, breathable feel. The vibrant print design is created with exceptional clarity, while reinforced stitching ensures durability. Versatile and sustainable, this t-shirt is a must-have addition to your wardrobe.", "With our user-friendly customization options, you can bring your vision to life, making a statement that is truly your own. Elevate your style today with our extraordinary Printed Cotton T-Shirt.", "Join us in our commitment to sustainability with our environmentally friendly materials and production processes."]',
        1500,
        '/shirt.png',
        2
    );

CREATE TABLE IF NOT EXISTS `customizations` (
    `id` VARCHAR(36) NOT NULL,
    `text` TEXT NOT NULL,
    `font` TEXT,
    `color` TEXT,
    `width` TEXT NOT NULL,
    `height` TEXT NOT NULL,
    `x` TEXT NOT NULL,
    `y` TEXT NOT NULL,
    `base_product` VARCHAR(36) NOT NULL,
    PRIMARY KEY (`id`),
    FOREIGN KEY (`base_product`) REFERENCES `base_custom_product`(`id`)
);

CREATE TABLE IF NOT EXISTS `order` (
    `id` VARCHAR(36) NOT NULL,
    `user` VARCHAR(36) NOT NULL,
    `name` TEXT NOT NULL,
    `surname` TEXT NOT NULL,
    `address` TEXT NOT NULL,
    `city` TEXT NOT NULL,
    `country` TEXT NOT NULL,
    PRIMARY KEY (`id`),
    FOREIGN KEY (`user`) REFERENCES `users`(`id`)
);

CREATE TABLE IF NOT EXISTS `order_items` (
    `id` INT AUTO_INCREMENT NOT NULL,
    `order` VARCHAR(36) NOT NULL,
    `item` VARCHAR(36) NOT NULL,
    `qty` INT NOT NULL,
    PRIMARY KEY (`id`),
    FOREIGN KEY (`order`) REFERENCES `order`(`id`)
);