# Database FAQ

This database is a serialized `set()` of all Bitcoin addresses with a positive balance.

The database was created using a third-party program: <a href="https://github.com/graymauser/btcposbal2csv">btcposbal2csv</a> which generates a csv file of all Bitcoin addresses with a positive balance. The csv file was converted into a set and the set was serialized into several `.pickle` files each holding 1,000,000 P2PKH Bitcoin addresses. When the program runs, the files in the database get deserialized and combined to be used for a balance query.

The name of the database folder is the date when the database was last updated in month_day_year format. The database will be updated every 3-6 months.

### How Many Addresses Does The Database Have?

The database currently holds `33,165,253 Bitcoin addresses`. This is the total number of P2PKH Bitcoin addresses with a balance that exist in the blockchain (on March 15 2021)

### Why Are There So Many Files?

There are multiple `.pickle` files because GitHub limits file uploads to 50 MB. The single serialized file is too large, so it was split into multiple files each under 50 MB in order to be uploaded to GitHub.
