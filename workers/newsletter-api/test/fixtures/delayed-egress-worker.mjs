// Fixture: responds immediately, then performs egress from waitUntil. The test
// drains the registered promise without assuming how quickly the response arrives.
export default {
  async fetch(_request, _env, ctx) {
    ctx.waitUntil(
      new Promise((resolve) => setTimeout(resolve, 200)).then(() =>
        fetch('https://delayed-provider.runtime-suite.invalid/send'),
      ),
    );
    return new Response('ok');
  },
};
