import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://peacexf.github.io',
  base: '/seta',
  integrations: [
    starlight({
      title: 'Seta',
      description: 'Posture monitoring as code for public-facing infrastructure.',
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/PeacexF/seta' }],
      sidebar: [
        { label: 'Start here', items: ['quickstart', 'dns-resolvers'] },
        { label: 'Checks', items: [{ autogenerate: { directory: 'checks' } }] },
      ],
    }),
  ],
});
