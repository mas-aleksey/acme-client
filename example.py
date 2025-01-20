import asyncio

from acme_client import ACMEClient, ACMESettings, RSAKey


async def dns_01_example() -> None:
    acc_key = RSAKey.new()
    le_conf = ACMESettings(
        HOST="https://acme-v02.api.letsencrypt.org/directory",
        EMAIL="X9wBk@example.com",
    )
    domains = ["example.com", "www.example.com"]

    async with ACMEClient(le_conf) as le_client:
        # create account
        acc_kid = await le_client.new_account(acc_key)

        # create order
        order, order_url = await le_client.new_order(acc_key, domains, acc_kid)

        # get authorization
        for authorization in order.authorizations:

            # get authorization info for each domain
            challenges = await le_client.get_auth_info(acc_key, authorization, acc_kid)

            # dns-01 example
            txt_record_name = f"_acme-challenge.{challenges.identifier.value}"
            txt_record_value = acc_key.validate(challenges.dns_01_challenge.token)

            # TODO:
            #  1. make txt record in your dns provider
            #  2. wait for dns record to be resolved

            # when ensure that dns record is resolved we can mark challenge as done
            await le_client.say_challenge_is_done(acc_key, challenges.dns_01_challenge.url, acc_kid)

            # wait a bit for challenge to be done
            for _ in range(30):
                challenge = await le_client.get_auth_info(acc_key, authorization, acc_kid)
                if challenge.status != "pending":
                    break
                await asyncio.sleep(1)
            if challenges.status != "valid":
                raise ValueError("invalid challenge")

        # when all challenges are done we can mark order as done
        cert_key = RSAKey.new()
        csr = cert_key.make_csr(domains[0], alternative_names=domains[1:])
        await le_client.finalize_order(acc_key, order.finalize, csr, acc_kid)

        # wait a bit for order to be done
        for _ in range(30):
            order = await le_client.get_order_info(acc_key, order_url, acc_kid)
            if order.status != "pending":
                break
            await asyncio.sleep(1)
        if order.status != "valid":
            raise ValueError("invalid order")

        # when order is done we can download certificate
        if order.certificate is None:
            raise ValueError("certificate not found")
        full_chain = await le_client.download_chain(acc_key, order.certificate, acc_kid)

        # well done, we can save certificate to disk or do something with it
        print(full_chain)
