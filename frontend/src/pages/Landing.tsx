import { Hero } from '../components/Hero';
import { Features } from '../components/Features';
import { Architecture } from '../components/Architecture';
import { CodeDemo } from '../components/CodeDemo';

export function Landing() {
  return (
    <main>
      <Hero />
      <Features />
      <Architecture />
      <CodeDemo />
    </main>
  );
}
