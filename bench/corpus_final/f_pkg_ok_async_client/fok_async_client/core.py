import aiohttp


async def get(path):
    async with aiohttp.ClientSession() as s:
        async with s.get('https://api.example.org/v1/' + path) as r:
            return await r.json()
