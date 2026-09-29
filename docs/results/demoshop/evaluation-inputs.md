# 입력점별 취약 유형 — demoshop

- 입력점 103개 · 취약 42개 (SQLi 13 · Reflected XSS 19 · BAC 10) · 안전 61개

| # | 경로 | 파라미터 | 위치 | 취약 유형 |
| ---: | --- | --- | --- | --- |
| 1 | `/account/address` | `address_id` | QUERY | **BAC** |
| 2 | `/account/address` | `city` | QUERY | **Reflected XSS** |
| 3 | `/account/address` | `street` | QUERY | 안전 |
| 4 | `/account/address` | `zipcode` | QUERY | 안전 |
| 5 | `/account/login` | `next` | QUERY | 안전 |
| 6 | `/account/login` | `return_to` | QUERY | **Reflected XSS** |
| 7 | `/account/login` | `username` | QUERY | **Reflected XSS** |
| 8 | `/account/points` | `period` | QUERY | 안전 |
| 9 | `/account/points` | `uid` | QUERY | 안전 |
| 10 | `/account/profile` | `bio` | QUERY | **Reflected XSS** |
| 11 | `/account/profile` | `nickname` | QUERY | **Reflected XSS** |
| 12 | `/account/profile` | `uid` | QUERY | **BAC** |
| 13 | `/account/profile` | `view` | QUERY | 안전 |
| 14 | `/account/wishlist` | `page` | QUERY | 안전 |
| 15 | `/account/wishlist` | `sort` | QUERY | 안전 |
| 16 | `/account/wishlist` | `uid` | QUERY | **BAC** |
| 17 | `/admin/orders` | `id` | QUERY | **BAC** |
| 18 | `/admin/orders` | `status` | QUERY | 안전 |
| 19 | `/admin/users` | `id` | QUERY | **BAC** |
| 20 | `/admin/users` | `q` | QUERY | **SQLi** |
| 21 | `/admin/users` | `role` | QUERY | 안전 |
| 22 | `/api/suggest` | `limit` | QUERY | 안전 |
| 23 | `/api/suggest` | `term` | QUERY | **Reflected XSS** |
| 24 | `/blog/post` | `comment` | QUERY | **Reflected XSS** |
| 25 | `/blog/post` | `slug` | QUERY | 안전 |
| 26 | `/blog/post` | `sort` | QUERY | 안전 |
| 27 | `/blog/search` | `q` | QUERY | **SQLi** |
| 28 | `/cart` | `coupon` | QUERY | **SQLi** |
| 29 | `/cart` | `item_id` | QUERY | 안전 |
| 30 | `/cart` | `note` | QUERY | 안전 |
| 31 | `/cart` | `qty` | QUERY | 안전 |
| 32 | `/catalog` | `brand` | QUERY | **SQLi** |
| 33 | `/catalog` | `category` | QUERY | 안전 |
| 34 | `/catalog` | `color` | QUERY | 안전 |
| 35 | `/catalog` | `page` | QUERY | 안전 |
| 36 | `/catalog` | `size` | QUERY | 안전 |
| 37 | `/catalog` | `sort` | QUERY | **SQLi** |
| 38 | `/checkout` | `message` | QUERY | 안전 |
| 39 | `/checkout` | `order_ref` | QUERY | **Reflected XSS** |
| 40 | `/checkout` | `payment` | QUERY | 안전 |
| 41 | `/checkout` | `shipping` | QUERY | 안전 |
| 42 | `/checkout` | `zipcode` | QUERY | 안전 |
| 43 | `/compare` | `ids` | QUERY | **SQLi** |
| 44 | `/compare` | `sort` | QUERY | 안전 |
| 45 | `/newsletter` | `email` | QUERY | 안전 |
| 46 | `/newsletter` | `source` | QUERY | 안전 |
| 47 | `/order/invoice` | `format` | QUERY | 안전 |
| 48 | `/order/invoice` | `order_id` | QUERY | **BAC** |
| 49 | `/order/track` | `carrier` | QUERY | 안전 |
| 50 | `/order/track` | `tracking_no` | QUERY | **SQLi** |
| 51 | `/orders` | `from_date` | QUERY | 안전 |
| 52 | `/orders` | `order_id` | QUERY | **SQLi** |
| 53 | `/orders` | `status` | QUERY | 안전 |
| 54 | `/orders` | `to_date` | QUERY | 안전 |
| 55 | `/portal/card` | `card_id` | QUERY | 안전 |
| 56 | `/portal/message` | `thread` | QUERY | **BAC** |
| 57 | `/portal/order` | `ref` | QUERY | **BAC** |
| 58 | `/product` | `id` | QUERY | **SQLi** |
| 59 | `/product` | `qty` | QUERY | 안전 |
| 60 | `/product` | `tab` | QUERY | 안전 |
| 61 | `/product` | `variant` | QUERY | **Reflected XSS** |
| 62 | `/product/qna` | `answered` | QUERY | 안전 |
| 63 | `/product/qna` | `product_id` | QUERY | 안전 |
| 64 | `/product/qna` | `q` | QUERY | **Reflected XSS** |
| 65 | `/product/reviews` | `page` | QUERY | 안전 |
| 66 | `/product/reviews` | `product_id` | QUERY | **SQLi** |
| 67 | `/product/reviews` | `rating` | QUERY | 안전 |
| 68 | `/product/reviews` | `sort` | QUERY | 안전 |
| 69 | `/promo/coupon` | `campaign` | QUERY | **Reflected XSS** |
| 70 | `/promo/coupon` | `code` | QUERY | **SQLi** |
| 71 | `/promo/event` | `banner` | QUERY | **Reflected XSS** |
| 72 | `/promo/event` | `event_id` | QUERY | 안전 |
| 73 | `/promo/event` | `utm_source` | QUERY | 안전 |
| 74 | `/review/new` | `body` | QUERY | 안전 |
| 75 | `/review/new` | `nickname` | QUERY | **Reflected XSS** |
| 76 | `/review/new` | `product_id` | QUERY | 안전 |
| 77 | `/review/new` | `rating` | QUERY | 안전 |
| 78 | `/review/new` | `title` | QUERY | **Reflected XSS** |
| 79 | `/search` | `category` | QUERY | 안전 |
| 80 | `/search` | `max_price` | QUERY | 안전 |
| 81 | `/search` | `min_price` | QUERY | 안전 |
| 82 | `/search` | `q` | QUERY | **Reflected XSS** |
| 83 | `/search` | `sort` | QUERY | 안전 |
| 84 | `/seller/dashboard` | `metric` | QUERY | 안전 |
| 85 | `/seller/dashboard` | `range` | QUERY | 안전 |
| 86 | `/seller/dashboard` | `seller_id` | QUERY | **SQLi** |
| 87 | `/seller/product/edit` | `price` | QUERY | 안전 |
| 88 | `/seller/product/edit` | `product_id` | QUERY | **SQLi** |
| 89 | `/seller/product/edit` | `stock` | QUERY | 안전 |
| 90 | `/seller/product/edit` | `title` | QUERY | **Reflected XSS** |
| 91 | `/seller/settlement` | `month` | QUERY | 안전 |
| 92 | `/seller/settlement` | `seller_id` | QUERY | **BAC** |
| 93 | `/store/locator` | `city` | QUERY | **Reflected XSS** |
| 94 | `/store/locator` | `radius` | QUERY | 안전 |
| 95 | `/store/locator` | `zip` | QUERY | 안전 |
| 96 | `/support/chat` | `nickname` | QUERY | **Reflected XSS** |
| 97 | `/support/chat` | `room` | QUERY | 안전 |
| 98 | `/support/faq` | `q` | QUERY | 안전 |
| 99 | `/support/faq` | `topic` | QUERY | 안전 |
| 100 | `/support/ticket` | `category` | QUERY | 안전 |
| 101 | `/support/ticket` | `message` | QUERY | 안전 |
| 102 | `/support/ticket` | `subject` | QUERY | **Reflected XSS** |
| 103 | `/support/ticket` | `ticket_id` | QUERY | **BAC** |
