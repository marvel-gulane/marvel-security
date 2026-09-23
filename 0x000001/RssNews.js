// asia-rss.js — run with: node asia-rss.js
const feeds =[ {
	name : 'BBC Asia', url : 'https://feeds.bbci.co.uk/news/world/asia/rss.xml'
}, {
	name : 'CNA', url : 'https://www.channelnewsasia.com/api/v1/rss-outbound-feed?_format=xml'
}, {
	name : 'SCMP', url : 'https://www.scmp.com/rss/3/rss.xml'
}, {
	name : 'Radio Free Asia', url : 'https://www.rfa.org/english/feed/rss2.xml'
}, {
	name : 'The Diplomat', url : 'https://thediplomat.com/feed/'
}, {
	name : 'East Asia Forum', url : 'https://eastasiaforum.org/feed/'
}, {
	name : 'e27', url : 'https://e27.co/feed/'
}, {
	name : 'Nikkei Asia', url : 'https://asia.nikkei.com/rss/feed/nar'
}, {
	name : 'Manila Bulletin', url : 'https://mb.com.ph/rss/'
}, {
	name : 'GMA News', url : 'https://data.gmanews.tv/gno/rss/news/feed.xml'
}, {
	name : 'PhilStar News', url : 'https://www.philstar.com/rss/headlines'
}, {
	name : 'Manila Standard', url : 'https://manilastandard.net/feed/all'
}, {
	name : 'Business World', url : 'https://www.bworldonline.com/feed/'
}, {
	name : 'Rappler News', url : 'https://www.rappler.com/rss'
}, {
	name : 'Interaksyon TV5', url : 'https://www.interaksyon.com/feed/'
}, {
	name : 'Current Ph', url : 'https://currentph.com/feed/'
}, {
	name : 'Panay Island News', url : 'https://panaynews.net/feed'
},];
function extract(text) {
	const items =[];
	for(const m of text.matchAll( / < item[\s\S] * ? < \ / item > / g)) {
		const b = m[0];
		const get =(t) =>(b.match(new RegExp(`<${t}[^>]*>([\\s\\S]*?)</${t}>`)) ||[])[1] ?. replace( / < ! \[CDATA\[([\s\S] * ?) \] \] > /, '$1') ?. trim();
		items.push( {
			title : get('title'), link : get('link'), pubDate : get('pubDate')
		});
	}
	return items;
}
async
function main() {
	const results = await Promise.allSettled(feeds.map(async( {
		name, url
	}) => {
		const res = await fetch(url, {
			headers : {
				'User-Agent' : 'Mozilla/5.0'
			}
		});
		const text = await res.text();
		return {
			name, items : extract(text)
		};
	}));
	for(const r of results) {
		if(r.status != = 'fulfilled') {
			console.log('⚠️  failed');
			continue;
		}
		const {
			name, items
		}
		= r.value;
		console.log(`\n=== ${name} (${items.length} items) ===`);
		for(const it of items.slice(0, 5)) {
			console.log(`  ${it.title}\n    ${it.link}`);
		}
	}
}
main();
