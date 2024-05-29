// @generated automatically by Diesel CLI.

diesel::table! {
    csrftokens (id) {
        id -> Integer,
        token -> Text,
    }
}

diesel::table! {
    products (id) {
        id -> Integer,
        price -> Integer,
        name -> Text,
        description -> Text,
        image_src -> Text,
        image_credits -> Text,
    }
}

diesel::table! {
    users (id) {
        id -> Integer,
        username -> Text,
        password -> Text,
        token -> Nullable<Text>,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    csrftokens,
    products,
    users,
);
